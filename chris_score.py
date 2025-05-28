import sys
import json
import requests

def get_cve_base_score_from_nvd(cve_id):
    """
    Fetches CVE data from the NVD API and extracts the baseScore
    where the source is 'nvd@nist.gov'.

    Returns:
        float or None: The baseScore if found, otherwise None.
    """
    nvd_api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    print(f"Fetching data from: {nvd_api_url}")

    try:
        response = requests.get(nvd_api_url)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
        data = response.json()

        extracted_base_score = None

        if "vulnerabilities" in data and len(data["vulnerabilities"]) > 0:
            for vulnerability in data["vulnerabilities"]:
                if "cve" in vulnerability and "metrics" in vulnerability["cve"] and "cvssMetricV31" in vulnerability["cve"]["metrics"]:
                    for metric in vulnerability["cve"]["metrics"]["cvssMetricV31"]:
                        if "source" in metric and metric["source"] == "nvd@nist.gov" and "cvssData" in metric and "baseScore" in metric["cvssData"]:
                            extracted_base_score = metric["cvssData"]["baseScore"]
                            return extracted_base_score # Return once found
        return None # No baseScore found for nvd@nist.gov source
    except requests.exceptions.HTTPError as err_h:
        print(f"Http Error: {err_h}")
        return None
    except requests.exceptions.ConnectionError as err_c:
        print(f"Error Connecting: {err_c}")
        return None
    except requests.exceptions.Timeout as err_t:
        print(f"Timeout Error: {err_t}")
        return None
    except requests.exceptions.RequestException as err:
        print(f"Something went wrong with the request: {err}")
        return None
    except json.JSONDecodeError:
        print("Failed to decode JSON response.")
        return None

def calculate_vulnerability_score(
    is_kev: bool,
    cvss_base_score: float,
    epss_score: float,
    asset_criticality: str
) -> int:
    """
    Calculates an overall vulnerability risk score (0-100) based on hierarchical rules.

    Args:
        is_kev (bool): True if the vulnerability is in the CISA KEV catalog, False otherwise.
        cvss_base_score (float): The CVSS Base Score (0.0 to 10.0).
        epss_score (float): The EPSS score (0.0 to 1.0, representing 0-100%).
        asset_criticality (str): The criticality of the affected asset.
                                 Accepted values: 'critical', 'high', 'medium', 'low'.

    Returns:
        int: An overall risk score between 0 and 100, where 100 is highest risk.
    """

    score = 0  # Initialize score

    # --- Step 1: KEV (Highest Priority) ---
    # If a vulnerability is in KEV, it's immediately critical.
    if is_kev:
        # Assign a very high base score, then add modifiers.
        # This ensures KEV always pushes it to the highest tier.
        score = 85 # Base for actively exploited vulnerabilities

        # Add a bonus based on EPSS and CVSS for actively exploited ones
        score += int(epss_score * 10)  # Up to +10 for EPSS (e.g., 0.9 EPSS adds 9)
        score += int(cvss_base_score * 0.5) # Up to +5 for CVSS (e.g., CVSS 10 adds 5)

        # Cap at 100, as this is already in the highest risk category
        return min(score, 100)

    # --- Step 2: EPSS Score (High Probability of Exploitation) ---
    # EPSS indicates how likely it is to be exploited in the wild.
    # Higher EPSS, higher immediate risk.
    if epss_score >= 0.9:  # 90% or higher probability
        score = 75
    elif epss_score >= 0.7:  # 70-89% probability
        score = 60
    elif epss_score >= 0.5:  # 50-69% probability
        score = 45
    elif epss_score >= 0.2:  # 20-49% probability
        score = 30
    else:
        score = 10 # Base for lower EPSS, will be influenced by CVSS and Asset Criticality

    # --- Step 3: CVSS Base Score (Technical Severity) ---
    # Adjust score based on CVSS, with diminishing returns as EPSS already sets a base.
    if cvss_base_score >= 9.0: # Critical
        score += 15
    elif cvss_base_score >= 7.0: # High
        score += 10
    elif cvss_base_score >= 4.0: # Medium
        score += 5
    # For CVSS < 4.0, minimal or no direct score addition at this stage

    # --- Step 4: Asset Criticality (Business Impact) ---
    # This is crucial for internal prioritization.
    # You'll need to get asset_criticality from an internal asset inventory.
    if asset_criticality.lower() == 'critical':
        score += 15
    elif asset_criticality.lower() == 'high':
        score += 10
    elif asset_criticality.lower() == 'medium':
        score += 5
    # 'low' asset criticality adds no additional score here

    # --- Final Score Clamping ---
    # Ensure the score stays within the 0-100 range.
    return min(max(0, int(score)), 100)

# --- Main Script Execution ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python your_script_name.py <CVE_ID>")
        sys.exit(1)

    cve_id = sys.argv[1].upper() # Get CVE ID from command line, convert to uppercase for consistency
    print(f"\033[34mProcessing CVE: {cve_id}\033[0m\n")

    # 1. Get KEV status from https://kevin.gtfkd.com/kev/exists?cve={cve_id}
    is_kev = False # Default to False if not found or API fails
    kev_api_url = f"https://kevin.gtfkd.com/kev/exists?cve={cve_id}"
    try:
        response = requests.get(kev_api_url)
        response.raise_for_status() # Raise an exception for HTTP errors
        kev_data = response.json()
        is_kev = kev_data.get("In_KEV", True)
        print(f"KEV Status: {'In KEV' if is_kev else 'Not in KEV'}")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching KEV data for {cve_id}: {e}")
    except json.JSONDecodeError:
        print(f"Error decoding KEV JSON for {cve_id}")

    # 2. Get EPSS score from https://api.first.org/data/v1/epss?cve={cve_id}
    epss_score = 0.0 # Default to 0.0 if not found or API fails
    epss_api_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        response = requests.get(epss_api_url)
        response.raise_for_status()
        epss_data = response.json()
        # EPSS API returns data in a list under 'data' key
        if epss_data and epss_data.get('data') and len(epss_data['data']) > 0:
            epss_score = float(epss_data['data'][0].get('epss', 0.0))
        print(f"EPSS Score: {epss_score:.4f}")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching EPSS data for {cve_id}: {e}")
    except (json.JSONDecodeError, KeyError, IndexError):
        print(f"Error decoding or parsing EPSS JSON for {cve_id}")

    # 3. Get CVSS score and CVE severity from https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json
    print("\n \033[32mRed Hat\033[0m")
    cvss_base_score = 0.0 # Default to 0.0 if not found or API fails
    cve_severity = "unknown" # Default
    redhat_api_url = f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"
    try:
        response = requests.get(redhat_api_url)
        response.raise_for_status()
        redhat_data = response.json()
        if 'cvss3' in redhat_data and 'cvss3_base_score' in redhat_data['cvss3']:
            cvss_base_score = float(redhat_data['cvss3']['cvss3_base_score'])
        if 'threat_severity' in redhat_data:
            cve_severity = redhat_data['threat_severity'].lower()
        print(f"- CVSS Base Score: {cvss_base_score}")
        print(f"- CVE Severity: {cve_severity.capitalize()}")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching Red Hat data for {cve_id}: {e}")
    except (json.JSONDecodeError, KeyError):
        print(f"Error decoding or parsing Red Hat JSON for {cve_id}")

    # Get the CVSS Score from NVD
    print(f"\n \033[32mNVD\033[0m")

    cvss_base_score_nvd = 0.0 # Default to 0.0 if not found or API fails
    nvd_api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        response = requests.get(nvd_api_url)
        response.raise_for_status()
        nvd_data = response.json()
        if "vulnerabilities" in nvd_data and len(nvd_data["vulnerabilities"]) > 0:
            for vulnerability in nvd_data["vulnerabilities"]:
                if "cve" in vulnerability and "metrics" in vulnerability["cve"] and "cvssMetricV31" in vulnerability["cve"]["metrics"]:
                    for metric in vulnerability["cve"]["metrics"]["cvssMetricV31"]:
                        if "source" in metric and metric["source"] == "nvd@nist.gov" and "cvssData" in metric and "baseScore" in metric["cvssData"]:
                            cvss_base_score_nvd = metric["cvssData"]["baseScore"]

        print(f"- CVSS Base Score: {cvss_base_score_nvd}")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching NVD data for {cve_id}: {e}")
    except (json.JSONDecodeError, KeyError):
        print(f"Error decoding or parsing NVD JSON for {cve_id}")

    # --- CRITICAL DECISION POINT: Mapping CVE Severity to Asset Criticality ---
    # This is a placeholder. In a real system, asset_criticality should come
    # from an internal asset inventory or CMDB, NOT directly from CVE severity.
    # For this script, we'll map Red Hat's severity to a placeholder asset criticality.
    # This is an oversimplification and should be improved in a production system.
    if cve_severity == 'critical':
        asset_criticality = 'critical'
    elif cve_severity == 'important': # Red Hat uses 'Important' for High
        asset_criticality = 'high'
    elif cve_severity == 'moderate': # Red Hat uses 'Moderate' for Medium
        asset_criticality = 'medium'
    elif cve_severity == 'low':
        asset_criticality = 'low'
    else:
        # Default for unknown severity or if Red Hat API didn't provide one
        asset_criticality = 'medium' # A reasonable default for unknown

    print(f"Assumed Asset Criticality (based on CVE Severity placeholder): {asset_criticality.capitalize()}")

    print("-----------------------------------------------------------------\n")


    # Calculate the final score
    final_score = calculate_vulnerability_score(
        is_kev=is_kev,
        cvss_base_score=cvss_base_score,
        epss_score=epss_score,
        asset_criticality=asset_criticality
    )

    print(f"\033[31mCommon Hierarchical Risk Intelligence Score (CHRIS) for {cve_id}: {final_score}/100\033[0m \n")