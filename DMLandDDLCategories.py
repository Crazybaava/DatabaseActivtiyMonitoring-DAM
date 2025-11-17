import re
def categorize_dml_ddl(df):
    if df.empty:
        return 0, 0
        
    dml_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE"]
    
    ddl_dcl_patterns = re.compile(
        r'^\s*(CREATE|DROP|ALTER|TRUNCATE|GRANT|REVOKE)\s+(?:DATABASE|SCHEMA|TABLE|USER|ROLE|PASSWORD|INDEX|VIEW|PROCEDURE|FUNCTION)', 
        re.IGNORECASE
    )
    
    df_queries = df[df["command"].str.contains("query|execute|prepare", case=False, na=False)].copy()

    dml_count = 0
    ddl_count = 0
    
    def get_query_type(q):
        if not isinstance(q, str): return "OTHER"
        q_stripped = q.strip()
        if not q_stripped: return "OTHER"
            
        if ddl_dcl_patterns.match(q_stripped):
            return "DDL"

        q_upper_word = q_stripped.split(None, 1)[0].upper()
        if q_upper_word in dml_keywords: 
            return "DML"
            
        return "OTHER"
        
    df_queries["query_type"] = df_queries["query"].apply(get_query_type)
    
    dml_count = len(df_queries[df_queries["query_type"] == "DML"])
    ddl_count = len(df_queries[df_queries["query_type"] == "DDL"])
    
    return dml_count, ddl_count