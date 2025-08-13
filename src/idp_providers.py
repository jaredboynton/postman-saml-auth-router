#!/usr/bin/env python3
"""
Identity Provider Abstraction Layer for Postman Authentication Router
Supports multiple SAML IDPs through a common interface
"""

import logging

logger = logging.getLogger('IDPProviders')


class IDPProvider:
    """Abstract base for Identity Provider implementations"""
    
    def get_auth_url(self, relay_state):
        """Generate authentication URL with relay state"""
        raise NotImplementedError
    
    def get_logout_url(self):
        """Generate logout URL"""
        raise NotImplementedError
    
    def get_display_name(self):
        """Get human-readable provider name"""
        raise NotImplementedError


class OktaProvider(IDPProvider):
    """Okta SAML Identity Provider"""
    
    def __init__(self, config):
        self.idp_url = config['idp_url']
        self.app_id = config.get('okta_app_id', '')
        logger.info(f"Initialized Okta provider with URL: {self.idp_url}")
    
    def get_auth_url(self, relay_state):
        return f"{self.idp_url}?RelayState={relay_state}"
    
    def get_logout_url(self):
        return f"{self.idp_url}/logout"
    
    def get_display_name(self):
        return "Okta"


class AzureProvider(IDPProvider):
    """Azure AD SAML Identity Provider"""
    
    def __init__(self, config):
        self.tenant_id = config['tenant_id']
        self.app_id = config['app_id']
        self.base_url = f"https://login.microsoftonline.com/{self.tenant_id}/saml2"
        logger.info(f"Initialized Azure AD provider for tenant: {self.tenant_id}")
    
    def get_auth_url(self, relay_state):
        return f"{self.base_url}?RelayState={relay_state}"
    
    def get_logout_url(self):
        return f"{self.base_url}/logout"
    
    def get_display_name(self):
        return "Azure AD"


class PingProvider(IDPProvider):
    """Ping Identity SAML Provider"""
    
    def __init__(self, config):
        self.idp_url = config['idp_url']
        self.connection_id = config.get('connection_id', '')
        logger.info(f"Initialized Ping Identity provider with URL: {self.idp_url}")
    
    def get_auth_url(self, relay_state):
        return f"{self.idp_url}?RelayState={relay_state}"
    
    def get_logout_url(self):
        return f"{self.idp_url}/logout"
    
    def get_display_name(self):
        return "Ping Identity"


class OneLoginProvider(IDPProvider):
    """OneLogin SAML Provider"""
    
    def __init__(self, config):
        self.idp_url = config['idp_url']
        self.app_id = config.get('app_id', '')
        logger.info(f"Initialized OneLogin provider with URL: {self.idp_url}")
    
    def get_auth_url(self, relay_state):
        return f"{self.idp_url}?RelayState={relay_state}"
    
    def get_logout_url(self):
        return f"{self.idp_url}/logout"
    
    def get_display_name(self):
        return "OneLogin"


# Provider registry
IDP_PROVIDERS = {
    'okta': OktaProvider,
    'azure': AzureProvider,
    'ping': PingProvider,
    'onelogin': OneLoginProvider
}


def create_idp_provider(config):
    """Factory function to create IDP provider from config"""
    idp_type = config.get('idp_type', 'okta').lower()
    
    if idp_type not in IDP_PROVIDERS:
        available = ', '.join(IDP_PROVIDERS.keys())
        raise ValueError(f"Unsupported IDP type: {idp_type}. Available: {available}")
    
    provider_class = IDP_PROVIDERS[idp_type]
    return provider_class(config)


def get_supported_providers():
    """Get list of supported IDP provider types"""
    return list(IDP_PROVIDERS.keys())