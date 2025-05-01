import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import queue
import time
import threading
from pathlib import Path
import logging
import re

class WebCrawler:
    def __init__(self):
        self.visited_urls = set()
        self.internal_links = set()
        self.external_links = set()
        self.progress_queue = queue.Queue()
        self.stop_flag = False
        self.pages_crawled = 0
        self.start_time = None

    def clear_progress(self):
        while not self.progress_queue.empty():
            self.progress_queue.get()
        self.visited_urls.clear()
        self.internal_links.clear()
        self.external_links.clear()
        self.pages_crawled = 0
        self.stop_flag = False

    def is_valid_url(self, url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    def is_internal_url(self, base_domain, url):
        return urlparse(url).netloc == base_domain

    def get_domain(self, url):
        return urlparse(url).netloc

    def crawl(self, start_url, max_depth=2, max_pages=100, respect_robots=True):
        try:
            if not self.is_valid_url(start_url):
                raise ValueError("Invalid URL provided")

            self.start_time = time.time()
            base_domain = self.get_domain(start_url)
            queue_to_crawl = [(start_url, 0)]  # (url, depth)
            self.visited_urls = set()
            self.internal_links = set()
            self.external_links = set()
            
            while queue_to_crawl and not self.stop_flag:
                if self.pages_crawled >= max_pages:
                    break

                current_url, depth = queue_to_crawl.pop(0)
                if depth > max_depth:
                    continue

                if current_url in self.visited_urls:
                    continue

                try:
                    response = requests.get(current_url, timeout=10)
                    self.visited_urls.add(current_url)
                    self.pages_crawled += 1

                    # Update progress
                    progress = (self.pages_crawled / max_pages) * 100
                    self.progress_queue.put({
                        'progress': min(progress, 100),
                        'pages_crawled': self.pages_crawled,
                        'links_found': len(self.internal_links) + len(self.external_links),
                        'current_url': current_url,
                        'finished': False
                    })

                    if response.status_code == 200:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        for link in soup.find_all('a'):
                            href = link.get('href')
                            if href:
                                absolute_url = urljoin(current_url, href)
                                if self.is_valid_url(absolute_url):
                                    if self.is_internal_url(base_domain, absolute_url):
                                        self.internal_links.add(absolute_url)
                                        if depth < max_depth:
                                            queue_to_crawl.append((absolute_url, depth + 1))
                                    else:
                                        self.external_links.add(absolute_url)

                except Exception as e:
                    logging.error(f"Error crawling {current_url}: {str(e)}")
                    continue

            # Send final results
            self.progress_queue.put({
                'progress': 100,
                'pages_crawled': self.pages_crawled,
                'links_found': len(self.internal_links) + len(self.external_links),
                'internal_links': list(self.internal_links),
                'external_links': list(self.external_links),
                'time_taken': f"{time.time() - self.start_time:.2f} seconds",
                'finished': True
            })

        except Exception as e:
            self.progress_queue.put({
                'error': str(e),
                'finished': True
            })

    def stop(self):
        self.stop_flag = True

    def get_progress(self):
        try:
            return self.progress_queue.get_nowait()
        except queue.Empty:
            return None
