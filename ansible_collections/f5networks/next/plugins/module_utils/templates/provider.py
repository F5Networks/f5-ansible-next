create = """
{
  "name": "{{ params.name }}",
  "type": "{{ params.type }}",
  "connection": {
    "host": "{{ params.host }}",
    {% if params.cert_fingerprint is defined %}
    "cert_fingerprint": "{{ params.cert_fingerprint }}",
    {% endif %}
    "authentication": {
      "type": "basic",
      "username": "{{ params.username }}",
      "password": "{{ params.password }}"
    }
  }
}
"""
