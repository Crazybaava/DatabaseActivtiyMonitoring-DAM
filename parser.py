def parse_log_line(line):
    try:
        first_comma_index = line.find(',')
        if first_comma_index == -1: return None
        
        second_comma_index = line.find(',', first_comma_index + 1)
        if second_comma_index == -1: return None 
             
        core_log_data = line[second_comma_index + 1:].strip()
        
        if not core_log_data: return None

        parts = core_log_data.rsplit(",", 2) 
        
        if len(parts) < 3: return None 
        core_fixed = parts[0].split(",", 8)
        
        if len(core_fixed) != 9: return None
            
        timestamp_utc = core_fixed[0].strip()
        server_host = core_fixed[1].strip()
        user = core_fixed[2].strip()
        Source_IP = core_fixed[3].strip()
        connection_id = core_fixed[4].strip()
        query_id = core_fixed[5].strip()
        command = core_fixed[6].strip()
        db = core_fixed[7].strip()
        queryandstatus = core_fixed[8].strip().strip("'")
        query_str = queryandstatus.rsplit(',',1)[0]
        if command == "QUERY":
            status_str = queryandstatus.rsplit(',',1)[1]
        else:
            status_str = parts[1].strip()

        status = int(status_str) if status_str.isdigit() else 0

        return {
            "timestamp_utc": timestamp_utc,
            "server_host": server_host,
            "user": user,
            "Source_IP": Source_IP,
            "connection_id": connection_id,
            "query_id": query_id,
            "command": command,
            "db": db,
            "query": query_str,
            "status": status
        }
    except IndexError:
        return None
    except Exception:
        return None