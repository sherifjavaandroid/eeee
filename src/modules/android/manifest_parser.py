import xml.etree.ElementTree as ET
import logging
from pathlib import Path
from typing import Dict, List, Any

class ManifestParser:
    def __init__(self, manifest_path: str):
        self.manifest_path = Path(manifest_path)
        self.logger = logging.getLogger(__name__)
        self.tree = None
        self.root = None
        self.namespaces = {
            'android': 'http://schemas.android.com/apk/res/android'
        }

    def parse(self) -> bool:
        """Parse AndroidManifest.xml"""
        try:
            self.tree = ET.parse(self.manifest_path)
            self.root = self.tree.getroot()
            return True
        except Exception as e:
            self.logger.error(f"Failed to parse manifest: {e}")
            return False

    def get_package_name(self) -> str:
        """Get package name from manifest"""
        if self.root is None:
            self.parse()
        return self.root.get('package', '')

    def get_permissions(self) -> List[str]:
        """Get list of requested permissions"""
        if self.root is None:
            self.parse()

        permissions = []
        for elem in self.root.findall('.//uses-permission'):
            perm = elem.get('{http://schemas.android.com/apk/res/android}name')
            if perm:
                permissions.append(perm)

        return permissions

    def get_exported_components(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get all exported components"""
        if self.root is None:
            self.parse()

        components = {
            'activities': [],
            'services': [],
            'receivers': [],
            'providers': []
        }

        # Find exported activities
        for activity in self.root.findall('.//activity'):
            if self._is_exported(activity):
                components['activities'].append(self._get_component_info(activity))

        # Find exported services
        for service in self.root.findall('.//service'):
            if self._is_exported(service):
                components['services'].append(self._get_component_info(service))

        # Find exported receivers
        for receiver in self.root.findall('.//receiver'):
            if self._is_exported(receiver):
                components['receivers'].append(self._get_component_info(receiver))

        # Find exported providers
        for provider in self.root.findall('.//provider'):
            if self._is_exported(provider):
                components['providers'].append(self._get_component_info(provider))

        return components

    def get_security_issues(self) -> List[Dict[str, Any]]:
        """Get security issues from manifest"""
        if self.root is None:
            self.parse()

        issues = []

        # Check debuggable flag
        app_elem = self.root.find('.//application')
        if app_elem is not None:
            debuggable = app_elem.get('{http://schemas.android.com/apk/res/android}debuggable')
            if debuggable == 'true':
                issues.append({
                    'type': 'debuggable_app',
                    'severity': 'High',
                    'description': 'Application is debuggable',
                    'location': 'AndroidManifest.xml'
                })

            # Check allowBackup
            allow_backup = app_elem.get('{http://schemas.android.com/apk/res/android}allowBackup')
            if allow_backup == 'true':
                issues.append({
                    'type': 'backup_allowed',
                    'severity': 'Medium',
                    'description': 'Application allows backup',
                    'location': 'AndroidManifest.xml'
                })

            # Check cleartext traffic
            cleartext = app_elem.get('{http://schemas.android.com/apk/res/android}usesCleartextTraffic')
            if cleartext == 'true':
                issues.append({
                    'type': 'cleartext_traffic',
                    'severity': 'High',
                    'description': 'Application allows cleartext traffic',
                    'location': 'AndroidManifest.xml'
                })

        # Check for dangerous permissions
        dangerous_permissions = [
            'android.permission.READ_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.SEND_SMS',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.CALL_PHONE',
            'android.permission.READ_CALL_LOG',
            'android.permission.WRITE_CALL_LOG',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO'
        ]

        requested_permissions = self.get_permissions()
        for perm in requested_permissions:
            if perm in dangerous_permissions:
                issues.append({
                    'type': 'dangerous_permission',
                    'severity': 'Medium',
                    'description': f'Uses dangerous permission: {perm}',
                    'location': 'AndroidManifest.xml'
                })

        return issues

    def _is_exported(self, component: ET.Element) -> bool:
        """Check if component is exported"""
        exported = component.get('{http://schemas.android.com/apk/res/android}exported')

        if exported == 'true':
            return True
        elif exported == 'false':
            return False
        else:
            # If not explicitly set, check for intent-filters
            intent_filters = component.findall('.//intent-filter')
            return len(intent_filters) > 0

    def _get_component_info(self, component: ET.Element) -> Dict[str, Any]:
        """Get component information"""
        info = {
            'name': component.get('{http://schemas.android.com/apk/res/android}name', ''),
            'permission': component.get('{http://schemas.android.com/apk/res/android}permission', ''),
            'exported': component.get('{http://schemas.android.com/apk/res/android}exported', 'implicit'),
            'intent_filters': []
        }

        # Get intent filters
        for intent_filter in component.findall('.//intent-filter'):
            filter_info = {
                'actions': [],
                'categories': [],
                'data': []
            }

            for action in intent_filter.findall('.//action'):
                action_name = action.get('{http://schemas.android.com/apk/res/android}name')
                if action_name:
                    filter_info['actions'].append(action_name)

            for category in intent_filter.findall('.//category'):
                category_name = category.get('{http://schemas.android.com/apk/res/android}name')
                if category_name:
                    filter_info['categories'].append(category_name)

            for data in intent_filter.findall('.//data'):
                data_info = {}
                for attr in ['scheme', 'host', 'port', 'path', 'pathPrefix', 'pathPattern', 'mimeType']:
                    value = data.get('{http://schemas.android.com/apk/res/android}' + attr)
                    if value:
                        data_info[attr] = value
                if data_info:
                    filter_info['data'].append(data_info)

            info['intent_filters'].append(filter_info)

        return info