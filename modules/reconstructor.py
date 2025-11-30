"""
reconstructor.py

takes in .json web content as input and tries to reconstruct web pages from data as output
"""

# native libraries
import json, base64, gzip, os, re, hashlib, argparse
import brotli
import zlib
from io import BytesIO
from urllib.parse import urlparse, unquote
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# 3rd party libraries
try:
    from bs4 import BeautifulSoup
except ImportError:
    print("bs4 not installed: try pip install beautifulsoup4")
    BeautifulSoup = None

class Reconstructor:
    """
    process .json HTTP data and reconstruct web pages
    """
    def __init__(self, jsonfile: str, outputdir: str="reconstructed_sites"):
        """
        initialise class

        args:
        jsonfile(str) - path to .json capture file
        outputdir(str) - directory to save pages into
        """
        self.jsonfile = jsonfile
        self.outputdir = Path(outputdir)
        self.outputdir.mkdir(exist_ok=True)
        self.data = []
        self.resources_map = {}
        self.cached_pages = []

    def load_data(self) -> bool:
        """
        load and parse file

        args:
        N/A

        returns:
        bool - True or False depending on .json loading was successful
        """
        try:
            with open(self.jsonfile, 'r', encoding='utf-8') as f:
                self.data = json.load(f)
            print(f"Loaded {len(self.data)} HTTP transactions")
            return True
        except Exception as e:
            print(f"Error loading .json file: {e}")
            return False
        
    def decode_body(self, entry: Dict) -> Optional[bytes]:
        """
        decode HTTP body from base 64, gunzip if needed

        args:
        entry(dict) - .json dictionary containing HTTP data

        returns:
        decoded body in bytes; returns nothing on failure
        """
        b64body = entry.get('resp_body_b64', '')
        if not b64body:
            return None
        
        try:
            body_bytes = base64.b64decode(b64body)

            # Check for content encoding header
            headers = entry.get('resp_headers', {})
            # Normalize headers to lowercase keys
            headers = {k.lower(): v for k, v in headers.items()}
            encoding = headers.get('content-encoding', '').lower()

            if 'br' in encoding:
                try:
                    body_bytes = brotli.decompress(body_bytes)
                except brotli.error as e:
                    print(f"Brotli decompression failed for {entry.get('url')}: {e}")
            elif 'gzip' in encoding or (len(body_bytes) >= 2 and body_bytes[:2] == b'\x1f\x8b'):
                try:
                    body_bytes = gzip.decompress(body_bytes)
                except gzip.BadGzipFile:
                    pass
            elif 'deflate' in encoding:
                try:
                    body_bytes = zlib.decompress(body_bytes)
                except zlib.error:
                    # Try raw deflate (no zlib header)
                    try:
                        body_bytes = zlib.decompress(body_bytes, -15)
                    except zlib.error:
                        pass

            return body_bytes
        except Exception as e:
            print(f"Error decoding HTTP body for {entry.get('url', 'unknown')}: {e}")
            return None
        
    def sanitise_filename(self, filename:str, max_length: int=100) -> str:
        """
        sanitise a filename for windows
        Truncates long file names & replaces them with a short hash instead

        args:
        filename(str) - original filename
        max_length(int) - maximum length for filename; default is 100

        returns:
        filename(str) - filename, sanitised for windows systems
        """
        # remove/replace invalid characters for windows
        filename = re.sub(r'[<>:"|?*\\\/]', '_', filename)
        filename = re.sub(r'[\x00-\x1f]', '', filename)

        # truncate filename
        if len(filename) > max_length:
            # keep extension
            parts = filename.split('.', 1)
            if len(parts) == 2 and len(parts[1]) <= 10:
                # has extension
                base = parts[0][:max_length - len(parts[1]) - 5] # leave room for hash
                hash_suffix = hashlib.md5(filename.encode()).hexdigest()[:4]
                filename = f"{base}_{hash_suffix}.{parts[1]}"
            else:
                # no extension or very long one
                hash_suffix = hashlib.md5(filename.encode()).hexdigest()[:4]
                filename = f"{filename[:max_length-5]}_{hash_suffix}"

        return filename
        
    def create_local_path(self, url:str, mime_type:str='') -> Path:
        """
        create local file path for given URL

        args:
        url(str) - input URL
        mime_type(str) - MIME type, helps determine file extension

        returns:
        Path object for local file path
        """
        parsed = urlparse(url)

        # create dir for domain
        domain_dir = self.outputdir / self.sanitise_filename(parsed.netloc.replace(':','_'))
        domain_dir.mkdir(exist_ok=True)

        # parse path & query separately
        path = parsed.path.strip('/')

        # split path into components, sanitise each one
        if path:
            path_parts = path.split('/')
            # limit depth
            if len(path_parts) > 4:
                # keep first 3 and last part
                path_parts = path_parts[:3] + [path_parts[-1]]

            # sanitise
            path_parts = [self.sanitise_filename(part, 50) for part in path_parts]

            # handle last part
            if path_parts:
                filename = path_parts[-1]

                # if there's query parameters, create hash-based filename
                if parsed.query:
                    # create hash of full URL
                    url_hash = hashlib.md5(url.encode()).hexdigest()[:8]

                    # determine mime type extension
                    ext =''
                    if 'html' in mime_type:
                        path+='.html'
                    elif 'javascript' in mime_type:
                        path+='.js'
                    elif 'css' in mime_type:
                        path+= '.css'
                    elif 'json' in mime_type:
                        path+= '.json'
                    elif 'image/gif' in mime_type:
                        path += '.gif'
                    elif 'image/png' in mime_type:
                        path+='.png'
                    elif 'image/jpg' in mime_type:
                        path+='.jpg'

                    else:
                        # use query parameters to make unique filename
                        if '.' in filename:
                            ext = '.' + filename.rsplit('.', 1)[1][:4] # limit extension

                        else:
                            ext='.html' # default

                    # create filename with hash
                    base_name = self.sanitise_filename(filename.split('.')[0], 30)
                    filename = f"{base_name}_{url_hash}{ext}"
                    path_parts[-1] = filename
                else:
                    # if there's no query parameters, then just ensure extension is there
                    if '.' not in filename:
                        if 'html' in mime_type:
                            path_parts[-1] = filename + '.html'
                        elif 'javascript' in mime_type:
                            path_parts[-1] = filename + '.js'
                        elif 'json' in mime_type:
                            path_parts[-1] = filename + '.json'
            
            # reconstruct path
            if len(path_parts) > 1:
                # create subdirs
                subdir = domain_dir
                for i in path_parts[:-1]:
                    subdir = subdir / i
                    try:
                        subdir.mkdir(exist_ok=True)
                    except OSError as e:
                        # if cannot create directory, flatten directory structure
                        print(f"Error: Cannot create deep directory, flattening: {e}")
                        filename = '_'.join(path_parts)
                        return domain_dir / self.sanitise_filename(filename, 100)
                    
                local_path = subdir / path_parts[-1]
            else:
                local_path = domain_dir / (path_parts[0] if path_parts else 'index.html')
        else:
            # no path, create index instead
            local_path = domain_dir / 'index.html'

        # check 1 more time to ensure full path isn't too long
        if len(str(local_path)) > 250:
            # Use hash if path is too long
            url_hash = hashlib.md5(url.encode()).hexdigest()[:12]
            ext = '.html'
            if 'javascript' in mime_type:
                ext = '.js'
            elif 'json' in mime_type:
                ext = '.json'
            elif 'image' in mime_type:
                if 'gif' in mime_type:
                    ext = '.gif'
                elif 'png' in mime_type:
                    ext = '.png'
                elif 'jpeg' in mime_type or 'jpg' in mime_type:
                    ext = '.jpg'
            
            local_path = domain_dir / f"file_{url_hash}{ext}"


        return local_path
    
    def proc_html_content(self, html: str, baseurl: str) -> str:
        """
        process HTML content to get/update resource links

        args:
        html(str) - original HTML code
        baseurl(str) - base URL for resolving relative links

        returns:
        soup(str) - HTML content with updated links
        """
        if not BeautifulSoup:
            return html
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            parsed_base = urlparse(baseurl)

            # update links for various tags
            tag_attr_pairs = [
                ('link', 'href'),
                ('script', 'src'),
                ('img', 'src'),
                ('a', 'href'),
                ('iframe', 'src'),
            ]

            for tagname, attrname in tag_attr_pairs:
                for i in soup.find_all(tagname):
                    originalurl = i.get(attrname)
                    if originalurl:
                        # skip data URL and anchor
                        if originalurl.startswith(('data:', '#', 'javascript:', 'mailto:')):
                            continue

                        # convert to absolute URL
                        if originalurl.startswith('//'):
                            absurl = f"https://{originalurl}"
                        elif originalurl.startswith('/'):
                            absurl = f"{parsed_base.scheme}://{parsed_base.netloc}{originalurl}"
                        elif not originalurl.startswith(('http://', 'https://')):
                            # use relative URL
                            basepath = '/'.join(baseurl.split('/')[:-1])
                            absurl = f"{basepath}/{originalurl}"
                        else:
                            absurl = originalurl

                        # check if resource exists locally
                        if absurl in self.resources_map:
                            # update to local path
                            localpath = self.resources_map[absurl]
                            try:
                                rel_path = os.path.relpath(localpath, Path(baseurl).parent)
                                i[attrname] = rel_path.replace('\\', '/')
                            except ValueError:
                                # can't create relative path
                                i[attrname] = str(localpath).replace('\\', '/')

            return str(soup)
        except Exception as e:
            print(f"Error processing HTML: {e}")
            return html
    
    def analyse_capture(self) -> Dict:
        """
        analyse capture data
        return stats

        args:
        N/A

        returns:
        stats(dict) - stats on what was captured in the .json file
        """
        stats={
            'total_requests':len(self.data),
            'methods':{},
            'status_codes':{},
            'content_types':{},
            'domains':set(),
            'html_pages':0,
            'resources':{
                'images':0,
                'scripts':0,
                'stylesheets':0,
                'json':0
            }
        }

        for i in self.data:
            # methods
            method = i.get('method', 'unknown')
            stats['methods'][method]=stats['methods'].get(method, 0) + 1

            # status codes
            status = i.get('status', 'unknown')
            stats['status_codes'][status]=stats['status_codes'].get(status,0) + 1

            # domains
            url = i.get('url', '')
            if url:
                parsed=urlparse(url)
                stats['domains'].add(parsed.netloc)

            # content types
            mime = i.get('mime_type', '').lower()
            if mime:
                stats['content_types'][mime] = stats['content_types'].get(mime, 0 ) + 1

                # count resources within mime
                if 'html' in mime:
                    stats['html_pages'] += 1
                elif 'image' in mime:
                    stats['resources']['images'] += 1
                elif 'javascript' in mime:
                    stats['resources']['scripts'] += 1
                elif 'css' in mime:
                    stats['resources']['stylesheets'] += 1
                elif 'json' in mime:
                    stats['resources']['json'] += 1

        stats['domains'] = list(stats['domains'])
        return stats
    
    def reconstruct(self, filter_domains: Optional[List[str]] = None) -> int:
        """
        reconstruct web pages from capture data

        args:
        filter_domains(list) - optional list of domains to process

        returns:
        pages(int) - number of pages reconstructed
        """
        pages =0

        # pass 1: save all resources, build resource map from capture
        print("\nSaving captured resources...")
        for i in self.data:
            url = i.get('url', '')
            if not url:
                continue

            # apply domain filter, if there are any
            if filter_domains:
                parsed=urlparse(url)
                if parsed.netloc not in filter_domains:
                    continue

            # process code 200 responses with content
            status = i.get('status_code', 0)
            if status not in range(200, 300):
                continue

            # decode response body
            body = self.decode_body(i)
            if not body:
                continue

            # create local path
            mime_type = i.get('mime_type', '')
            try:
                localpath = self.create_local_path(url, mime_type)

                # save into resource map
                self.resources_map[url] = localpath

                # save all non-HTML resources as it is
                if 'html' not in mime_type.lower():

                        with open(localpath, 'wb') as f:
                            f.write(body)
                        print(f"Saved: {localpath.name} ({mime_type})")
            except Exception as e:
                print(f"Error saving {url[:80]}: {e}")

        # pass 2: process & save HTML pages with updated links
        print("\nProcessing HTML pages...")
        for i in self.data:
            url=i.get('url', '')
            mime_type = i.get('mime_type', '').lower()

            if not url or 'html' not in mime_type:
                continue

            # apply domain filter if any
            if filter_domains:
                parsed=urlparse(url)
                if parsed.netloc not in filter_domains:
                    continue

            # only process successful status codes
            status = i.get('status_code', 0)
            
            # Handle cached pages (304)
            if status == 304:
                parsed = urlparse(url)
                self.cached_pages.append((url, parsed.netloc))
                continue

            if status not in range(200, 300):
                continue

            # decode response body
            body = self.decode_body(i)
            if not body:
                continue

            try:
                # decode HTML
                html = body.decode('utf-8', errors='ignore')

                # update resource links
                if BeautifulSoup:
                    html = self.proc_html_content(html, url)

                # save HTML file
                localpath = self.resources_map.get(url)
                if localpath:
                    with open(localpath, 'w', encoding='utf-8') as f:
                        f.write(html)
                    print(f"Reconstructed {localpath}")
                    pages += 1

            except Exception as e:
                print(f"Error processing {url[:80]}: {e}")

        return pages
    
    def create_index_page(self):
        """
        Creates an index page listing all captured & reconstructed pages.
        """
        index_html = """<!DOCTYPE html>
                    <html>
                    <head>
                        <title>Reconstructed Pages Index</title>
                        <style>
                            body {{ font-family: Arial, sans-serif; margin: 20px; }}
                            h1 {{ color: #333; }}
                            .domain {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                            .domain h2 {{ color: #666; margin-top: 0; }}
                            ul {{ list-style-type: none; padding: 0; }}
                            li {{ margin: 5px 0; }}
                            a {{ color: #0066cc; text-decoration: none; }}
                            a:hover {{ text-decoration: underline; }}
                            .stats {{ background: #f5f5f5; padding: 10px; border-radius: 3px; margin-bottom: 20px; }}
                        </style>
                    </head>
                    <body>
                        <h1>Reconstructed Web Pages</h1>
                        <div class="stats">
                            <strong>Statistics:</strong><br>
                            Total reconstructed files: {total_files}<br>
                            HTML pages: {html_count}<br>
                            Other resources: {resource_count}
                        </div>
                    """

        domains = {}
        html_count = 0
        resource_count = 0

        for root, dirs, files in os.walk(self.outputdir):
            for f in files:
                if f == 'index.html' and root == str(self.outputdir):
                    continue

                filepath = Path(root)/f
                rel_path = filepath.relative_to(self.outputdir)

                # get domain from path
                parts = str(rel_path).split(os.sep)
                if parts:
                    domain = parts[0]

                    if domain not in domains:
                        domains[domain] = []

                    domains[domain].append(str(rel_path).replace('\\','/'))

                    if f.endswith('.html'):
                        html_count += 1
                    else:
                        resource_count += 1

        # Add cached pages to domains
        for url, domain in self.cached_pages:
            if domain not in domains:
                domains[domain] = []
            # Add with a special marker to identify it as cached
            domains[domain].append(f"CACHED:{url}")

        # add domains to index
        for domain, files in sorted(domains.items()):
            index_html += f'    <div class="domain">\n'
            index_html += f'        <h2>🌐 {domain}</h2>\n'
            index_html += f'        <ul>\n'
            
            # Filter for HTML files only
            html_files = [f for f in files if f.endswith('.html')]
            if not html_files:
                continue

            html_files.sort()
            
            for file in html_files[:20]:  # Limit to 20 files per domain
                # Truncate long filenames for display
                display_name = file if len(file) <= 80 else file[:77] + '...'
                
                if file.startswith("CACHED:"):
                    url = file.replace("CACHED:", "")
                    display_name = url if len(url) <= 80 else url[:77] + '...'
                    index_html += f'            <li><span style="color: #888;">{display_name}</span> <span class="file-type" style="background: #eee; color: #666;" title="Content was cached (304 Not Modified) and could not be reconstructed">[CACHED]</span></li>\n'
                else:
                    index_html += f'            <li><a href="{file}" title="{file}">{display_name}</a></li>\n'
            
            if len(html_files) > 20:
                index_html += f'            <li><em>... and {len(html_files) - 20} more files</em></li>\n'
            
            index_html += f'        </ul>\n'
            index_html += f'    </div>\n'
        
        index_html = index_html.format(
            total_files=html_count + resource_count,
            html_count=html_count,
            resource_count=resource_count
        )
        
        index_html += """
                        </body>
                        </html>
                        """
        
        # save index file
        index_path = self.outputdir/'index.html'
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(index_html)

        print(f"\nCreated index page: {index_path}")

def main():
    """
    main function
    """
    parser= argparse.ArgumentParser(description='Reconstruct HTML web pages from input .json')
    parser.add_argument('json_file', help='path to .json capture file')
    parser.add_argument('-o', '--output', default='reconstructed_sites', 
                        help='specify output directory(default is named "reconstructed_sites")')
    parser.add_argument('-d', '--domains', nargs='+',
                        help='filter specific domains from .json capture to reconstruct')
    parser.add_argument('-a', '--analysis-only', action='store_true',
                        help='only analyse capture without any reconstruction')
    
    args = parser.parse_args()

    # create processor
    processor = Reconstructor(args.json_file, args.output)

    # load data
    if not processor.load_data():
        return 1
    
    # analyse capture
    print("\nCapture Analysis:")
    stats = processor.analyse_capture()
    print(f"Total requests: {stats['total_requests']}")
    print(f"HTML pages: {stats['html_pages']}")
    print(f"Domains: {len(stats['domains'])}")
    print(f"Methods: {stats['methods']}")
    print(f"Top content types:")
    for mime, count in sorted(stats['content_types'].items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"- {mime}: {count}")

    if args.analysis_only:
        return 0
    
    print(f"\nReconstructing pages...")
    try:
        count = processor.reconstruct(args.domains)

        if count > 0:
            # create index page
            processor.create_index_page()
            print(f"\nSuccessfully reconstructed {count} HTML pages")
            print(f"Output directory in {processor.outputdir.absolute()}")
        else:
            print(f"""Warning: No HTML pages reconstructed; 
                capture may not have HTML responses, 
                responses are encrypted/binary, 
                or there was a processing error""")
    except Exception as e:
        print(f"Fatal error during reconstruction: {e}")
        import traceback
        traceback.print_exc()
        return 1
        
    return 0

if __name__ == '__main__':
    exit(main())
