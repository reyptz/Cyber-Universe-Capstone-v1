"""
HTTP Crawler Module
High-performance HTTP crawler with async requests
"""

import aiohttp
import asyncio
from typing import Dict, Any, List
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging

from .base_crawler import BaseCrawler, CrawlResult

logger = logging.getLogger("shinra.crawlers.http")

class HTTPCrawler(BaseCrawler):
    """
    HTTP crawler for standard web pages
    
    Features:
    - Async HTTP requests
    - HTML parsing with BeautifulSoup
    - Link extraction
    - Rate limiting
    - Timeout handling
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.session = None
        self.user_agent = config.get("user_agent", "Shinra-OSINT-Agent/1.0")
        self.headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
    
    async def __aenter__(self):
        """Context manager entry"""
        self.session = aiohttp.ClientSession(headers=self.headers)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        if self.session:
            await self.session.close()
    
    async def fetch(self, url: str) -> CrawlResult:
        """
        Fetch content from URL using aiohttp
        """
        if not self.session:
            self.session = aiohttp.ClientSession(headers=self.headers)
        
        try:
            async with self.session.get(url, timeout=self.timeout) as response:
                content = await response.text()
                
                result = CrawlResult(
                    url=url,
                    content=content,
                    metadata={
                        "status_code": response.status,
                        "content_type": response.content_type,
                        "headers": dict(response.headers)
                    },
                    timestamp=datetime.utcnow(),
                    hash=self.calculate_hash(content),
                    links=[],
                    error=None if response.status == 200 else f"HTTP {response.status}"
                )
                
                logger.info(f"Fetched {url}: {response.status} ({len(content)} bytes)")
                return result
        
        except asyncio.TimeoutError:
            logger.error(f"Timeout fetching {url}")
            return CrawlResult(
                url=url, content="", metadata={}, timestamp=datetime.utcnow(),
                hash="", links=[], error="Timeout"
            )
        
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            return CrawlResult(
                url=url, content="", metadata={}, timestamp=datetime.utcnow(),
                hash="", links=[], error=str(e)
            )
    
    async def parse(self, content: str, url: str) -> Dict[str, Any]:
        """
        Parse HTML content and extract links
        """
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Extract title
            title = soup.title.string if soup.title else ""
            
            # Extract meta tags
            meta_tags = {}
            for meta in soup.find_all('meta'):
                name = meta.get('name') or meta.get('property')
                content = meta.get('content')
                if name and content:
                    meta_tags[name] = content
            
            # Extract links
            links = []
            for link in soup.find_all('a', href=True):
                absolute_url = urljoin(url, link['href'])
                # Only follow same domain links
                if self._is_same_domain(url, absolute_url):
                    links.append(absolute_url)
            
            # Extract text
            text_content = soup.get_text(separator=' ', strip=True)
            
            return {
                "title": title,
                "meta_tags": meta_tags,
                "links": links[:50],  # Limit links to avoid explosion
                "text_content": text_content[:5000],  # Limit text
                "images_count": len(soup.find_all('img')),
                "scripts_count": len(soup.find_all('script')),
            }
        
        except Exception as e:
            logger.error(f"Error parsing {url}: {e}")
            return {"error": str(e)}
    
    def _is_same_domain(self, url1: str, url2: str) -> bool:
        """Check if two URLs are from the same domain"""
        return urlparse(url1).netloc == urlparse(url2).netloc


class APIClient(BaseCrawler):
    """
    API crawler for REST/JSON endpoints
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.api_key = config.get("api_key")
        self.session = None
    
    async def fetch(self, url: str) -> CrawlResult:
        """
        Fetch JSON data from API
        """
        if not self.session:
            headers = {"Accept": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self.session = aiohttp.ClientSession(headers=headers)
        
        try:
            async with self.session.get(url, timeout=self.timeout) as response:
                data = await response.json()
                content = str(data)  # Convert to string for storage
                
                return CrawlResult(
                    url=url,
                    content=content,
                    metadata={
                        "status_code": response.status,
                        "json_data": data,
                    },
                    timestamp=datetime.utcnow(),
                    hash=self.calculate_hash(content),
                    links=[],
                    error=None if response.status == 200 else f"HTTP {response.status}"
                )
        
        except Exception as e:
            logger.error(f"Error fetching API {url}: {e}")
            return CrawlResult(
                url=url, content="", metadata={}, timestamp=datetime.utcnow(),
                hash="", links=[], error=str(e)
            )
    
    async def parse(self, content: str, url: str) -> Dict[str, Any]:
        """
        Parse JSON data
        """
        return {"api_response": "parsed"}


# Performance test
async def test_crawler_performance():
    """
    Test crawler performance: target 1000 pages/minute
    """
    import time
    
    config = {
        "max_depth": 2,
        "delay": 0.01,  # 10ms delay = ~100 req/s
        "timeout": 10
    }
    
    test_urls = [
        "https://example.com",
        "https://example.org",
        "https://example.net",
    ]
    
    async with HTTPCrawler(config) as crawler:
        start_time = time.time()
        results = await crawler.crawl(test_urls)
        elapsed = time.time() - start_time
        
        pages_per_minute = (len(results) / elapsed) * 60
        
        print(f"Crawled {len(results)} pages in {elapsed:.2f}s")
        print(f"Performance: {pages_per_minute:.0f} pages/minute")
        print(f"Target: 1000 pages/minute")
        print(f"Status: {'✓ PASS' if pages_per_minute >= 1000 else '✗ FAIL'}")


if __name__ == "__main__":
    asyncio.run(test_crawler_performance())
