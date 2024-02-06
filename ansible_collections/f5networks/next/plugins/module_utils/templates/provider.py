create = """
{
  "name": "{{ params.name }}",
  "type": "{{ params.type }}",
  "connection": {
    "host": "{{ params.host }}",
    "authentication": {
      "type": "basic",
      "username": "{{ params.username }}",
      "password": "{{ params.password }}"
    }
  }
}
"""
