import base64

# Deduced from https://github.com/mmlab-aueb/PyEd25519Signature2018/blob/master/signer.py

def create_proof_signature(doc_hash, proof_hash, sign_fun):

    jws_header = b'{"alg":"EdDSA","crit":["b64"],"b64":false}'
    b64_header = base64.urlsafe_b64encode(jws_header)

    combined_hash =  b64_header + b'.' + proof_hash + doc_hash

    # Sign the hash
    proofbytes = sign_fun(combined_hash)

    jws = b64_header + b'..' + base64.urlsafe_b64encode(proofbytes)

    return jws.decode()[:-2]


def verify_proof(doc_hash, proof_hash, proof, verify_fun):
    [b64_header, b64_proof] = proof['jws'].split('..')

    combined_hash =  b64_header.encode() + b'.' + proof_hash + doc_hash

    # Extract signature bytes
    proof_bytes = base64.urlsafe_b64decode(b64_proof + '==')

    # Verify against the hash
    verify_fun(proof_bytes, combined_hash)