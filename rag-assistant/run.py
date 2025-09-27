#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Script d'entrée principal pour le RAG Assistant.
Ce script lance l'application FastAPI.
"""

import uvicorn
from app.api.main import app

if __name__ == "__main__":
    uvicorn.run("app.api.main:app", host="0.0.0.0", port=8000, reload=True)