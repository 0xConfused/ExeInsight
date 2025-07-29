import os
import json
import hashlib
import pefile
import requests
import logging
import argparse

# Replace with your VirusTotal API key
VIRUSTOTAL_API_KEY = "github_safe_version"

# Configure logging
def configure_logging(log_level):
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

def get_file_hash(filepath):
    """Generate SHA-256 hash of the given file."""
    sha256 = hashlib.sha256()
    logging.debug(f"Calculating SHA-256 for {filepath}")
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
    except Exception as e:
        logging.error(f"Error reading file {filepath}: {e}")
        return None
    return sha256.hexdigest()

def get_virustotal_detections(file_hash):
    """Query VirusTotal for the number of malicious detections."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    logging.debug(f"Querying VirusTotal for hash {file_hash}")
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        detections = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        logging.info(f"VirusTotal detections for {file_hash}: {detections}")
        return detections
    except requests.exceptions.RequestException as e:
        logging.error(f"Error querying VirusTotal for hash {file_hash}: {e}")
        return None
    except KeyError as e:
        logging.error(f"Unexpected VirusTotal response format: {e}")
        return None

def get_imports(filepath):
    """Extract imports from the PE file and structure them in the JSON format."""
    imports_data = {
        "import_sum": 0,
        "object_sum": 0
    }
    logging.debug(f"Extracting imports from {filepath}")
    
    try:
        pe = pefile.PE(filepath)

        # Process each DLL in the import table
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8")
            imports_data[dll_name] = {
                "imports": len(entry.imports)
            }
            
            # Record each import function as a boolean in the JSON structure
            for imp in entry.imports:
                func_name = imp.name.decode("utf-8") if imp.name else f"Ordinal_{imp.ordinal}"
                imports_data[dll_name][func_name] = 1
                imports_data["object_sum"] += 1
            
            imports_data["import_sum"] += 1
            
    except Exception as e:
        logging.error(f"Error extracting imports from {filepath}: {e}")

    return imports_data

def is_pe_file(filepath):
    """Check if the file is a PE file by reading the first two bytes."""
    try:
        with open(filepath, "rb") as f:
            magic_number = f.read(2)
            return magic_number == b'MZ'
    except Exception as e:
        logging.error(f"Error reading file {filepath}: {e}")
        return False

def process_exe_file(filepath, vt_query, output_folder):
    """Generate the JSON data structure for an EXE file."""
    logging.info(f"Processing file {filepath}")
    file_hash = get_file_hash(filepath)
    if file_hash is None:
        logging.error(f"Failed to hash file {filepath}")
        return
    
    vt_detections = get_virustotal_detections(file_hash) if vt_query else 0
    imports_data = get_imports(filepath)
    
    # Structure the JSON data as specified
    json_data = {
        "vt_detections": vt_detections,
        **imports_data
    }
    
    # Ensure the output directory exists
    os.makedirs(output_folder, exist_ok=True)

    # Write the JSON data to a file named by the hash of the EXE in the output folder
    output_file_path = os.path.join(output_folder, f"{file_hash}.json")
    try:
        with open(output_file_path, "w") as f:
            json.dump(json_data, f, indent=4)
        logging.info(f"Generated JSON file: {output_file_path}")
    except IOError as e:
        logging.error(f"Failed to write JSON file {output_file_path}: {e}")

def process_exe_files_in_folder(folder_path, vt_query, output_folder):
    """Process all PE files in a given folder."""
    logging.info(f"Processing folder {folder_path}")
    logging.debug(f"Files in directory: {os.listdir(folder_path)}")
    for filename in os.listdir(folder_path):
        filepath = os.path.join(folder_path, filename)
        if is_pe_file(filepath):
            logging.info(f"Found PE file: {filepath}")
            process_exe_file(filepath, vt_query, output_folder)
        else:
            logging.debug(f"Skipping non-PE file: {filename}")

def main():
    # Argument parser setup
    parser = argparse.ArgumentParser(description="Process PE files to extract import data.")
    parser.add_argument(
        '--log-level',
        type=str,
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Set the logging level'
    )
    parser.add_argument(
        '--no-vt-query',
        action='store_true',
        help='Disable querying VirusTotal'
    )
    parser.add_argument(
        '--output-folder',
        type=str,
        default='output',
        help='Specify the output folder for JSON files'
    )
    
    args = parser.parse_args()
    configure_logging(args.log_level)

    # Specify the folder containing the PE files
    folder_path = "./input"
    vt_query = not args.no_vt_query  # Enable VT query by default
    process_exe_files_in_folder(folder_path, vt_query, args.output_folder)

if __name__ == "__main__":
    main()