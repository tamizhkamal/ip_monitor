from ip2geotools.databases.noncommercial import DbIpCity

def get_ip_location(ip):
    try:
        response = DbIpCity.get(ip, api_key='free')
        return f"{response.city}, {response.country}"
    except:
        return "Unknown"
