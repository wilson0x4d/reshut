Overview
========

.. image:: https://img.shields.io/pypi/v/reshut.svg
   :target: https://pypi.org/project/reshut/
   :alt: reshut on PyPI

.. image:: https://readthedocs.org/projects/reshut/badge/?version=latest
   :target: https://reshut.readthedocs.io
   :alt: reshut on Read the Docs

**reshut** (רשות) is a decorative auth library for `Falcon <https://falconframework.org/>`_.

Features
--------

* **ASGI and WSGI middleware** for authorization, allowing multiple instances/configurations.
* **Decorators** that allow or deny access based on auth-token claims; extensible at a fine-grained level.
* **Algorithms**: HMAC (SHA-256/384/512), RSA (2048, 3072, ≥4096 bits), ECDSA (P-256, P-384, P-512), and EdDSA (Ed25519, Ed448).
* **JWK implementation** for key transmission or storage.
* **Utility functions** for key generation, claim tokenization, and token validation.
* **CLI Tools** which expose utility functions for Dev/QA/Ops use.
* ``Authorization`` and ``X-API-Key`` headers are supported.
* ``Bearer``, ``APIKEY``, and ``Basic`` schemes are supported.

Contents
--------

.. toctree::
   :maxdepth: 3

   Overview <self>
   Quick Start <quickstart>
   Reference <ref/index>
   MIT License <license>
   Contact <contact>
