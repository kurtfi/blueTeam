import os
import sys
import time
from playwright.sync_api import sync_playwright

CORTEX_URL = os.getenv("CORTEX_URL", "http://localhost:9001")

def main():
    print("=== Automating Cortex First-time Setup ===")
    print(f"Target: {CORTEX_URL}")
    
    with sync_playwright() as p:
        print("Launching headless browser...")
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        
        try:
            print("Navigating to Cortex...")
            page.goto(CORTEX_URL, timeout=60000)
            page.wait_for_load_state("domcontentloaded")
            
            # Print page title to verify
            print(f"Page title: {page.title()}")
            
            # Check if we need to update database
            # Typically a button with text "Update database" or class btn-primary
            print("Checking for 'Update database' button...")
            try:
                update_btn = page.locator("text=Update database")
                update_btn.wait_for(timeout=10000)
            except:
                pass
            
            if update_btn.count() > 0:
                print("Clicking 'Update database'...")
                update_btn.click()
                page.wait_for_timeout(5000)  # Wait for migration to finish
                page.wait_for_load_state("domcontentloaded")
                print("Database updated.")
            else:
                print("No 'Update database' button found. Maybe database is already updated.")
            
            # Check if we are on the first admin creation page
            # Usually has inputs for user details like login, name, password, confirm password
            print("Checking for Super Admin creation form...")
            
            # Look for password input or form
            try:
                password_input = page.locator("input[type='password']")
                password_input.nth(0).wait_for(timeout=10000)
            except:
                pass
            
            if password_input.count() > 0:
                print("Found admin registration form.")
                
                # Fill login/username (usually first text input)
                # Let's inspect the inputs
                text_inputs = page.locator("input[type='text']")
                email_inputs = page.locator("input[type='email']")
                
                # Fill Login (usually the first text input)
                if text_inputs.count() > 0:
                    text_inputs.nth(0).fill("admin")
                    print("Filled login with 'admin'")
                
                # Fill Name (usually the second text input)
                if text_inputs.count() > 1:
                    text_inputs.nth(1).fill("Super Admin")
                    print("Filled name with 'Super Admin'")
                elif email_inputs.count() > 0:
                    email_inputs.first.fill("admin@local.local")
                    print("Filled email with admin@local.local")

                # Fill password
                password_input.nth(0).fill("secret")
                print("Filled password with 'secret'")
                
                # Fill confirm password (second password input)
                if password_input.count() > 1:
                    password_input.nth(1).fill("secret")
                    print("Filled confirm password with 'secret'")
                
                # Click submit
                submit_btn = page.locator("button[type='submit']")
                if submit_btn.count() > 0:
                    print("Clicking submit button...")
                    submit_btn.click()
                else:
                    # Try clicking button with text "Create" or similar
                    create_btn = page.locator("text=Create")
                    if create_btn.count() > 0:
                        print("Clicking Create button...")
                        create_btn.click()
                    else:
                        print("Submit button not found. Pressing Enter...")
                        page.keyboard.press("Enter")
                
                page.wait_for_timeout(5000)
                page.wait_for_load_state("domcontentloaded")
                print("Form submitted successfully.")
            else:
                print("No admin registration form found. Admin might already be created.")
                
            # Take screenshot to verify state
            screenshot_path = "cortex_setup_status.png"
            page.screenshot(path=screenshot_path)
            print(f"Saved screenshot to {screenshot_path} to verify state.")
            
        except Exception as e:
            print(f"Error during automation: {e}")
            # Take error screenshot
            try:
                page.screenshot(path="cortex_error.png")
                print("Saved error screenshot to cortex_error.png")
            except:
                pass
        finally:
            browser.close()

if __name__ == "__main__":
    main()
