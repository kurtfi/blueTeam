import json
import os
import urllib.request

import structlog
import yaml

logger = structlog.get_logger(__name__)

API_URL = "https://api.github.com/repos/UraSecTeam/mordor/contents/datasets/metadata"
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}


def fetch_metadata_list():
    logger.info("compile_metadata.fetching_list_from_github", url=API_URL)
    req = urllib.request.Request(API_URL, headers=HEADERS)
    with urllib.request.urlopen(req) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_yaml_content(download_url):
    req = urllib.request.Request(download_url, headers=HEADERS)
    with urllib.request.urlopen(req) as response:
        return response.read().decode("utf-8")


def compile_mappings():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(current_dir, "mordor_mappings.json")

    try:
        files_list = fetch_metadata_list()
    except Exception as e:
        logger.error("compile_metadata.failed_to_fetch_list", error=str(e))
        return False

    mappings = {}
    logger.info("compile_metadata.processing_files", count=len(files_list))

    for item in files_list:
        name = item.get("name")
        download_url = item.get("download_url")
        if not name or not download_url or not name.endswith((".yaml", ".yml")):
            continue

        try:
            yaml_content = fetch_yaml_content(download_url)
            data = yaml.safe_load(yaml_content)
            if not data:
                continue

            # Extract attack mappings
            attack_mappings = data.get("attack_mappings", [])
            techniques = []
            tactics = []
            for mapping in attack_mappings:
                tech = mapping.get("technique")
                sub_tech = mapping.get("sub-technique")
                if tech:
                    full_tech = f"{tech}.{sub_tech}" if sub_tech else tech
                    techniques.append(full_tech)

                tacts = mapping.get("tactics", [])
                for t in tacts:
                    if t not in tactics:
                        tactics.append(t)

            # Get title and description
            title = data.get("title", "Unnamed Scenario")
            description = data.get("description", "")

            # Map each file listed in the metadata
            files = data.get("files", [])
            for f in files:
                link = f.get("link")
                if link:
                    filename = os.path.basename(link)
                    if filename:
                        mappings[filename.lower()] = {
                            "techniques": list(set(techniques)),
                            "tactics": tactics,
                            "title": title,
                            "description": description,
                        }

        except Exception as e:
            logger.error("compile_metadata.failed_to_parse_file", filename=name, error=str(e))

    # Save to JSON
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(mappings, f, indent=2, ensure_ascii=False)

    logger.info("compile_metadata.success", output_file=output_path, unique_files_mapped=len(mappings))
    return True


if __name__ == "__main__":
    compile_mappings()
