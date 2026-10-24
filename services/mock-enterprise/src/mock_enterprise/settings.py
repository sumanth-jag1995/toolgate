from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # No env prefix: IDP, SCOPE_PREFIX, JWT_AUDIENCE, ... map straight to fields.
    # hide_input_in_errors keeps a bad IDP value out of the startup error.
    model_config = SettingsConfigDict(hide_input_in_errors=True)

    database_url: str
    jwt_issuer: str
    jwks_url: str
    jwt_audience: str = "mock-enterprise"
    idp: Literal["keycloak", "cognito"] = "keycloak"
    scope_prefix: str = "mock-enterprise/"
