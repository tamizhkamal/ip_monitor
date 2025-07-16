from fastapi import Request
from models import UserIPLog
import smtplib

def get_client_ip(request: Request):
    return request.headers.get('x-forwarded-for', request.client.host)

def send_email_alert(user_email, ip):
    # Just for simulation
    print(f"🚨 ALERT: Login from new IP {ip} for {user_email}")

def is_new_ip(user, ip):
    known_ips = {log.ip_address for log in user.ip_logs}
    return ip not in known_ips

def count_distinct_ips(user):
    return len({log.ip_address for log in user.ip_logs})
