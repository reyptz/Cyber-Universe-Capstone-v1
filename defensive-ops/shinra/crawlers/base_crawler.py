"""
Base Crawler Module for Shinra OSINT Agent
Provides modular crawler architecture with pluggable modules
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass
import hashlib

logger = logging.getLogger("shinra.crawlers")

@dataclass
class CrawlResult:
    """Result from a crawl operation"""
    url: str
    content: str
    metadata: Dict[str, Any]
    timestamp: datetime
    hash: str
    links: List[str]
    error: Optional[str] = None

class BaseCrawler(ABC):
    """
    Base class for all crawler modules
    
    Performance target: 1000 pages/minute
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.max_depth = config.get("max_depth", 3)
        self.delay = config.get("delay", 0.1)  # Rate limiting
        self.timeout = config.get("timeout", 30)
        self.visited_urls = set()
        self.results = []
        
    @abstractmethod
    async def fetch(self, url: str) -> CrawlResult:
        """
        Fetch content from URL
        Must be implemented by subclasses
        """
        pass
    
    @abstractmethod
    async def parse(self, content: str, url: str) -> Dict[str, Any]:
        """
        Parse fetched content
        Must be implemented by subclasses
        """
        pass
    
    async def crawl(self, start_urls: List[str], depth: int = 0) -> List[CrawlResult]:
        """
        Main crawl method with breadth-first traversal
        """
        if depth > self.max_depth:
            return []
        
        logger.info(f"Crawling {len(start_urls)} URLs at depth {depth}")
        
        tasks = []
        for url in start_urls:
            if url not in self.visited_urls:
                self.visited_urls.add(url)
                tasks.append(self._crawl_url(url, depth))
        
        # Execute crawls concurrently for performance
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out errors and collect next level URLs
        next_urls = []
        for result in results:
            if isinstance(result, CrawlResult) and not result.error:
                self.results.append(result)
                next_urls.extend(result.links)
        
        # Recursive crawl for next depth
        if depth < self.max_depth and next_urls:
            await asyncio.sleep(self.delay)  # Rate limiting
            await self.crawl(next_urls, depth + 1)
        
        return self.results
    
    async def _crawl_url(self, url: str, depth: int) -> CrawlResult:
        """
        Crawl a single URL
        """
        try:
            logger.debug(f"Fetching {url} at depth {depth}")
            result = await self.fetch(url)
            
            # Parse content if successful
            if not result.error:
                parsed = await self.parse(result.content, url)
                result.metadata.update(parsed)
            
            return result
        
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")
            return CrawlResult(
                url=url,
                content="",
                metadata={},
                timestamp=datetime.utcnow(),
                hash="",
                links=[],
                error=str(e)
            )
    
    def calculate_hash(self, content: str) -> str:
        """Calculate content hash for deduplication"""
        return hashlib.sha256(content.encode()).hexdigest()
    
    def extract_metadata(self, content: str, url: str) -> Dict[str, Any]:
        """Extract basic metadata"""
        return {
            "url": url,
            "content_length": len(content),
            "timestamp": datetime.utcnow().isoformat(),
            "crawler_type": self.__class__.__name__
        }
