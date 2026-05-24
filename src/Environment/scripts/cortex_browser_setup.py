import os
import sys
import time
from playwright.sync_api import sync_playwright

CORTEX_URL = os.getenv("CORTEX_URL", "http://localhost:9001")
ADMIN_USER = "admin"
ADMIN_PASS = os.getenv("CORTEX_ADMIN_PASSWORD", "secret")

def update_env_files(api_key: str):
    """Updates CORTEX_API_KEY in the environment files."""
    env_paths = [
        "/Users/firatkurt/Documents/Repos/blueTeam/src/Environment/.env",
        "/Users/firatkurt/Documents/Repos/blueTeam/src/Agentix/.env"
    ]
    
    for env_path in env_paths:
        if not os.path.exists(env_path):
            print(f"  → Path not found: {env_path}")
            continue
            
        print(f"  → Updating {env_path}...")
        with open(env_path, "r") as f:
            lines = f.readlines()
            
        new_lines = []
        updated = False
        for line in lines:
            if line.startswith("CORTEX_API_KEY="):
                new_lines.append(f"CORTEX_API_KEY={api_key}\n")
                updated = True
            else:
                new_lines.append(line)
                
        if not updated:
            new_lines.append(f"\nCORTEX_API_KEY={api_key}\n")
            
        with open(env_path, "w") as f:
            f.writelines(new_lines)
        print(f"  ✓ Updated {env_path}")

def main():
    print("=== Cortex Browser-Based Setup ===")
    print(f"Target URL: {CORTEX_URL}")
    print(f"Admin User: {ADMIN_USER}")
    
    with sync_playwright() as p:
        print("Launching headless browser...")
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        
        try:
            print("Navigating to Cortex...")
            page.goto(f"{CORTEX_URL}/index.html#!/login")
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(2000)
            
            print("Filling login form...")
            # Cortex 3 login page typically has placeholders or inputs
            page.locator("input[placeholder='Login']").fill(ADMIN_USER)
            page.locator("input[placeholder='Password']").fill(ADMIN_PASS)
            
            print("Submitting login...")
            page.locator("button:has-text('Sign in')").click()
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(3000)
            
            print(f"Current URL after login attempt: {page.url}")
            
            # JS execution script to use AngularJS injector
            js_code = """
            async () => {
                const el = document.querySelector('[ng-app]') || document.body;
                const injector = angular.element(el).injector();
                if (!injector) {
                    throw new Error("AngularJS injector not found!");
                }
                const $http = injector.get('$http');
                
                let logInfo = [];
                
                // 1. Create organization 'agentix-lab'
                try {
                    const orgResp = await $http.post('/api/organization', {
                        name: 'agentix-lab',
                        description: 'Agentix MITRE ATT&CK Lab Organization',
                        status: 'Active'
                    });
                    logInfo.push("Org creation success: " + JSON.stringify(orgResp.data));
                } catch (err) {
                    logInfo.push("Org creation error/exists: " + err.status + " - " + JSON.stringify(err.data));
                }
                
                // 2. Create user 'agentix-analyst'
                try {
                    const userResp = await $http.post('/api/user', {
                        login: 'agentix-analyst',
                        name: 'Agentix Analyst',
                        roles: ['read', 'analyze', 'orgadmin'],
                        password: 'Agentix-Lab-2025!',
                        organization: 'agentix-lab'
                    });
                    logInfo.push("User creation success: " + JSON.stringify(userResp.data));
                } catch (err) {
                    logInfo.push("User creation error/exists: " + err.status + " - " + JSON.stringify(err.data));
                }
                
                // 3. Renew API key for 'agentix-analyst'
                try {
                    const keyResp = await $http.post('/api/user/agentix-analyst/key/renew');
                    // Clean/unwrap string if it contains extra quotes
                    let key = keyResp.data;
                    if (typeof key === 'string') {
                        key = key.replace(/^"|"$/g, '');
                    } else if (key && key.key) {
                        key = key.key;
                    }
                    return { success: true, apiKey: key, log: logInfo };
                } catch (err) {
                    return { success: false, error: 'Key renewal error: ' + err.status + " - " + JSON.stringify(err.data), log: logInfo };
                }
            }
            """
            
            print("Executing Angular automation in browser page context...")
            result = page.evaluate(js_code)
            
            print("\nBrowser Console Logs:")
            for log_line in result.get("log", []):
                print("  " + log_line)
                
            if result.get("success"):
                api_key = result.get("apiKey")
                print(f"\n✓ Successfully generated API key: {api_key}")
                update_env_files(api_key)
            else:
                print(f"\n✗ Setup failed: {result.get('error')}")
                sys.exit(1)
                
        except Exception as e:
            print(f"Error during browser automation: {e}")
            page.screenshot(path="cortex_browser_error.png")
            print("Saved error screenshot to cortex_browser_error.png")
            sys.exit(1)
        finally:
            browser.close()

if __name__ == '__main__':
    main()
