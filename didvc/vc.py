from pyld import jsonld
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from multibase import encode, decode
from jwcrypto import jwk, jwe, jwt
import json
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from datetime import datetime

def sign(credentials, key, did):

    # Canonize the Credentials
    canon_payload = jsonld.normalize(
        credentials, {'algorithm': 'URDNA2015', 'format': 'application/n-quads'})

    # Hash the canon payload
    digest = hashes.Hash(hashes.SHA256())
    digest.update(canon_payload.encode('utf8'))
    doc_hash = digest.finalize()

    #print(len(doc_hash)) # Should be 32

    # create the proof

    # convert the JWK into a PEM representation, required by cryptography.hazmat
    keypair = jwk.JWK.from_json(json.dumps(key))
    pkcs8Pem = keypair.export_to_pem(private_key=True, password=None)

    # Load private key using cryptography.hazmat.primitives
    private_key = load_pem_private_key(pkcs8Pem, password=None)
    #private_key = ed25519.Ed25519PrivateKey.from_private_bytes(privateBytes)

    # Sign the hash
    proofbytes = private_key.sign(doc_hash)
    #print(f"Length of proof signature: {len(proofbytes)}")

    ## is base64 the correct encoding ?
    proofValue = encode(data=proofbytes, encoding='base64')

    proof = {
        "type": "Ed25519Signature2020",
        "created": datetime.now().isoformat(sep='T',timespec='auto'),
        "verificationMethod": did+"#key-1",
        "proofPurpose": "assertionMethod",
        "proofValue": proofValue
    }

    return proof