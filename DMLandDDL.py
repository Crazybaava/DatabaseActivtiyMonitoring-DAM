import pandas as pd

def get_dml_ddl_breakdown(df):
    
    actions = {
        "updated tables": {"pattern": "UPDATE", "name": "Update Query"},
        "deleted tables": {"pattern": "DELETE", "name": "Delete Row Query"},
        "inserted tables": {"pattern": "INSERT", "name": "Insert Query"},
        "selected tables": {"pattern": "SELECT", "name": "Select Query"},
        
        "created databases": {"pattern": "CREATE\\s+(?:DATABASE|SCHEMA)", "name": "Created Databases/Schemas"},
        "altered databases": {"pattern": "ALTER\\s+(?:DATABASE|SCHEMA)", "name": "Altered Databases/Schemas"},
        "dropped databases": {"pattern": "DROP\\s+(?:DATABASE|SCHEMA)", "name": "Dropped Databases/Schemas"},
        "created tables": {"pattern": "CREATE\\s+TABLE", "name": "Created Tables"},
        "altered tables": {"pattern": "ALTER\\s+TABLE", "name": "Altered Tables"},
        "truncated tables": {"pattern": "TRUNCATE", "name": "Truncated Tables"},
        "dropped tables": {"pattern": "DROP\\s+TABLE", "name": "Dropped Tables"},

        "created users/roles": {"pattern": "CREATE\\s+(?:USER|ROLE)", "name": "Created Users/Roles"},
        "altered users/roles": {"pattern": "ALTER\\s+(?:USER|ROLE|PASSWORD)", "name": "Altered Users/Roles/Passwords"},
        "dropped users/roles": {"pattern": "DROP\\s+(?:USER|ROLE)", "name": "Dropped Users/Roles"},
    }

    DML_KEYS = [
        "updated tables", "deleted tables", "inserted tables", "selected tables"
    ]

    DDL_KEYS = [
        "created databases", "altered databases", "dropped databases",
        "created tables", "altered tables", "truncated tables", "dropped tables",
        "created users/roles", "altered users/roles", "dropped users/roles"
    ]
    
    if df.empty:
        dml_results = [{"Event Action": actions[k]["name"], "Success Count": 0, "Failed Count": 0} for k in DML_KEYS]
        ddl_results = [{"Event Action": actions[k]["name"], "Success Count": 0, "Failed Count": 0} for k in DDL_KEYS]
        return pd.DataFrame(dml_results), pd.DataFrame(ddl_results)

    df_queries = df[df["command"].str.contains("query|execute|prepare", case=False, na=False)].copy()
    
    df_queries['query_upper'] = df_queries["query"].str.strip().str.upper()

    dml_results = []
    ddl_results = []
    

    for key, action_info in actions.items():
        pattern = r"^\s*" + action_info["pattern"] + r"\b"
        name = action_info["name"]
        
        if key not in DML_KEYS and key not in DDL_KEYS:
            continue
            
        matching_queries = df_queries[df_queries['query_upper'].str.contains(pattern, regex=True, na=False)]
        
        success_count = int(matching_queries[matching_queries["status"] == 0].shape[0])
        failed_count = int(matching_queries[matching_queries["status"] != 0].shape[0])
        
        result = {
            "Event Action": name,
            "Success Count": success_count,
            "Failed Count": failed_count
        }

        if key in DML_KEYS:
            dml_results.append(result)
        elif key in DDL_KEYS:
            ddl_results.append(result)
            
    dml_df = pd.DataFrame(dml_results)
    ddl_df = pd.DataFrame(ddl_results)

    return dml_df, ddl_df