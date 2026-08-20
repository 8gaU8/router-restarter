from dotenv import load_dotenv

from router_restarter import restart_router

load_dotenv('router-restarter.env')
restart_router()
