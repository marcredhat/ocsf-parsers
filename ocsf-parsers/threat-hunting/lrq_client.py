#!/usr/bin/env python3
"""
LRQ Client - Long Running Query API client for SentinelOne PowerQuery
Supports string-based searches and regex matching at scale.
"""
import requests
import time
import os
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta


class LRQClient:
    """Client for SentinelOne Long Running Query API."""
    
    def __init__(self, console: str, jwt: str, rate_limit: float = 2.5):
        """
        Initialize LRQ client.
        
        Args:
            console: Console hostname (e.g., 'your-tenant.sentinelone.net')
            jwt: Bearer JWT token
            rate_limit: Requests per second (default 2.5 to stay under 3 rps limit)
        """
        self.console = console.rstrip('/')
        self.jwt = jwt
        self.rate_limit = rate_limit
        self.last_request_time = 0
        self.base_url = f"https://{self.console}/sdl/v2/api/queries"
    
    def _rate_limit_wait(self):
        """Enforce rate limiting."""
        elapsed = time.time() - self.last_request_time
        min_interval = 1.0 / self.rate_limit
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self.last_request_time = time.time()
    
    def _headers(self, forward_tag: Optional[str] = None) -> Dict[str, str]:
        """Build request headers."""
        headers = {
            "Authorization": f"Bearer {self.jwt}",
            "Content-Type": "application/json"
        }
        if forward_tag:
            headers["X-Dataset-Query-Forward-Tag"] = forward_tag
        return headers
    
    def launch_query(
        self,
        query: str,
        start_time: str,
        end_time: str,
        priority: str = "HIGH"
    ) -> Dict[str, Any]:
        """
        Launch a PowerQuery.
        
        Args:
            query: PowerQuery string
            start_time: ISO 8601 start time
            end_time: ISO 8601 end time
            priority: Query priority (HIGH, MEDIUM, LOW)
            
        Returns:
            Response dict with 'id' and 'forward_tag'
        """
        self._rate_limit_wait()
        
        body = {
            "queryType": "PQ",
            "tenant": True,
            "startTime": start_time,
            "endTime": end_time,
            "queryPriority": priority,
            "pq": {
                "query": query,
                "resultType": "TABLE"
            }
        }
        
        resp = requests.post(self.base_url, headers=self._headers(), json=body)
        resp.raise_for_status()
        
        data = resp.json()
        forward_tag = resp.headers.get("X-Dataset-Query-Forward-Tag", "")
        
        return {
            "id": data.get("id"),
            "forward_tag": forward_tag,
            "response": data
        }
    
    def poll_query(
        self,
        query_id: str,
        forward_tag: str,
        last_step: int = 0,
        timeout: int = 300,
        poll_interval: float = 1.5
    ) -> Dict[str, Any]:
        """
        Poll query until completion.
        
        Args:
            query_id: Query ID from launch
            forward_tag: Forward tag from launch response
            last_step: Last step seen (for resuming)
            timeout: Max seconds to wait
            poll_interval: Seconds between polls
            
        Returns:
            Final query result
        """
        start = time.time()
        steps_completed = last_step
        
        while time.time() - start < timeout:
            self._rate_limit_wait()
            
            resp = requests.get(
                f"{self.base_url}/{query_id}",
                headers=self._headers(forward_tag),
                params={"lastStepSeen": steps_completed}
            )
            resp.raise_for_status()
            data = resp.json()
            
            steps_completed = data.get("stepsCompleted", 0)
            steps_total = data.get("stepsTotal", 0)
            
            if steps_total > 0 and steps_completed >= steps_total:
                return data
            
            time.sleep(poll_interval)
        
        raise TimeoutError(f"Query {query_id} timed out after {timeout}s")
    
    def cancel_query(self, query_id: str, forward_tag: str):
        """Cancel/cleanup a query."""
        self._rate_limit_wait()
        
        resp = requests.delete(
            f"{self.base_url}/{query_id}",
            headers=self._headers(forward_tag)
        )
        return resp.status_code
    
    def execute_query(
        self,
        query: str,
        start_time: str,
        end_time: str,
        timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Execute a query end-to-end (launch, poll, cancel).
        
        Args:
            query: PowerQuery string
            start_time: ISO 8601 start time
            end_time: ISO 8601 end time
            timeout: Max seconds to wait
            
        Returns:
            Query results with columns and values
        """
        launch = self.launch_query(query, start_time, end_time)
        query_id = launch["id"]
        forward_tag = launch["forward_tag"]
        
        try:
            result = self.poll_query(query_id, forward_tag, timeout=timeout)
            return {
                "columns": result.get("data", {}).get("columns", []),
                "values": result.get("data", {}).get("values", []),
                "match_count": result.get("matchCount", 0),
                "status": "success"
            }
        finally:
            self.cancel_query(query_id, forward_tag)
    
    def execute_sliced_query(
        self,
        query: str,
        start_time: str,
        end_time: str,
        slice_days: int = 5,
        max_parallel: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Execute a query in time slices for large ranges.
        
        Args:
            query: PowerQuery string
            start_time: ISO 8601 start time
            end_time: ISO 8601 end time
            slice_days: Days per slice
            max_parallel: Max concurrent slices (limited by rate cap)
            
        Returns:
            List of results from each slice
        """
        start = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        end = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        
        slices = []
        current = start
        while current < end:
            slice_end = min(current + timedelta(days=slice_days), end)
            slices.append((
                current.strftime("%Y-%m-%dT%H:%M:%SZ"),
                slice_end.strftime("%Y-%m-%dT%H:%M:%SZ")
            ))
            current = slice_end
        
        results = []
        for slice_start, slice_end in slices:
            print(f"Executing slice: {slice_start} to {slice_end}")
            result = self.execute_query(query, slice_start, slice_end)
            results.append({
                "start": slice_start,
                "end": slice_end,
                "result": result
            })
        
        return results


def get_time_range(hours: int = 24) -> tuple:
    """Get ISO 8601 time range for last N hours."""
    end = datetime.utcnow()
    start = end - timedelta(hours=hours)
    return (
        start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        end.strftime("%Y-%m-%dT%H:%M:%SZ")
    )


if __name__ == "__main__":
    # Example usage
    CONSOLE = os.environ.get("S1_CONSOLE", "your-tenant.sentinelone.net")
    JWT = os.environ.get("S1_JWT", "your-jwt-token")
    
    client = LRQClient(CONSOLE, JWT)
    start, end = get_time_range(24)
    
    query = """
    dataSource.name='SentinelOne' dataSource.category='security'
    | group ct=count() by event.type
    | sort -ct
    | limit 20
    """
    
    print(f"Executing query from {start} to {end}")
    result = client.execute_query(query, start, end)
    
    print(f"\nColumns: {result['columns']}")
    print(f"Rows: {len(result['values'])}")
    for row in result['values'][:5]:
        print(f"  {row}")
