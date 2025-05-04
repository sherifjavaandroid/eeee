# {{ title }}

## Summary
{{ summary }}

## Vulnerability Type
{{ vulnerability_type }}

## Severity
**{{ severity }}**

## Description
{{ description }}

## Steps to Reproduce
{% for step in steps_to_reproduce %}
{{ loop.index }}. {{ step }}
{% endfor %}

## Impact
{{ impact }}

## Supporting Material/References
{% for material in supporting_material %}
- {{ material }}
  {% endfor %}

## Environment
- **Platform**: {{ app_info.platform }}
- **Application**: {{ app_info.package_name }}
- **Version**: {{ app_info.version }}
  {% if app_info.android_version %}
- **Android Version**: {{ app_info.android_version }}
  {% endif %}
  {% if app_info.ios_version %}
- **iOS Version**: {{ app_info.ios_version }}
  {% endif %}

## Proof of Concept