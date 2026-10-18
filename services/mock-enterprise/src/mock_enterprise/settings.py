from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str
    jwt_issuer: str
    jwks_url: str
    jwt_audience: str = "mock-enterprise"
