def get_flagged_destructive_actions(suspicious_df):
    flagged_actions = set()
    
    action_patterns = {
        "Update Query": r"^UPDATE",
        "Delete Row Query": r"^DELETE",
        "Insert Query": r"^INSERT", 
        "Truncated Tables": r"^TRUNCATE",
        "Created Databases/Schemas": r"^CREATE\s+(?:DATABASE|SCHEMA)",
        "Altered Databases/Schemas": r"^ALTER\s+(?:DATABASE|SCHEMA)",
        "Dropped Databases/Schemas": r"^DROP\s+(?:DATABASE|SCHEMA)",
        "Created Tables": r"^CREATE\s+TABLE",
        "Altered Tables": r"^ALTER\s+TABLE",
        "Dropped Tables": r"^DROP\s+TABLE",
        "Created Users/Roles": r"^CREATE\s+(?:USER|ROLE)",
        "Altered Users/Roles/Passwords": r"^ALTER\s+(?:USER|ROLE|PASSWORD)",
        "Dropped Users/Roles": r"^DROP\s+(?:USER|ROLE)",
    }
    
    if suspicious_df.empty:
        return flagged_actions
        
    df_temp = suspicious_df.copy()
    df_temp['query_upper'] = df_temp['query'].str.strip().str.upper()

    for name, pattern in action_patterns.items():
        if df_temp['query_upper'].str.contains(pattern, regex=True, na=False).any():
            flagged_actions.add(name)
            
    return flagged_actions