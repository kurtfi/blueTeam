import re

def test_logic(query):
    print(f"Testing: '{query}'")
    clean_query = query.strip()
    
    # 1. Remove Markdown code blocks if present
    if clean_query.startswith("```"):
        clean_query = clean_query.split("\n", 1)[-1]
        if "```" in clean_query:
            clean_query = clean_query.rsplit("```", 1)[0]
        clean_query = clean_query.strip()

    # 2. Strip comments
    while clean_query.startswith("--") or clean_query.startswith("/*"):
        if clean_query.startswith("--"):
            clean_query = clean_query.split("\n", 1)[1].strip() if "\n" in clean_query else ""
        else:
            clean_query = clean_query.split("*/", 1)[1].strip() if "*/" in clean_query else ""

    # 3. Heuristic: Check for common natural language patterns
    upper_query = clean_query.upper()
    if not (upper_query.startswith("SELECT") or upper_query.startswith("WITH")):
        # Simple heuristic for "LIST [ALL] TABLE" or "SHOW [ALL] TABLE"
        # Removes optional "all", "all from", "the", etc. for common phrasing
        match = re.match(r"^(?:LIST|SHOW)\s+(?:ALL\s+)?(?:FROM\s+)?(?:THE\s+)?([a-zA-Z0-9_]+)", upper_query)
        if match:
            table_name = match.group(1).lower()
            clean_query = f"SELECT * FROM {table_name}"
            upper_query = clean_query.upper()
            print(f"  Result: Transformed to '{clean_query}'")
        else:
            print(f"  Result: ERROR - Only read-only queries (SELECT, WITH) are permitted. Received: '{clean_query[:100]}'")
            return
    else:
        print(f"  Result: Valid SQL - '{clean_query}'")

    # 4. Security Check (simulated)
    forbidden = ["INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER", "CREATE", "GRANT", "REVOKE"]
    for word in forbidden:
        if f" {word} " in f" {upper_query} ":
            print(f"  Result: SECURITY ERROR - Operation '{word}' is not allowed.")
            return
    
    print("  Result: CHECK PASSED")

# Test Cases
test_logic("SELECT * FROM users")
test_logic("  LIST ALL USERS  ")
test_logic("List all users from the default database.")
test_logic("Show products")
test_logic("List the logs")
test_logic("WITH cte AS (SELECT 1) SELECT * FROM cte")
test_logic("DROP TABLE users")
test_logic("List all users; DROP TABLE users")
test_logic("Show me everything") # Should fail
