import base58

def create_proof_signature(doc_hash, proof_hash, sign_fun):

    # The hash to sign is the concatenation of the proof hash and the document hash,
    # as per https://www.w3.org/TR/vc-di-eddsa/#hashing-ed25519signature2020
    combined_hash = proof_hash + doc_hash

    # Sign the hash
    proofbytes = sign_fun(combined_hash)
    #print(f"Length of proof signature: {len(proofbytes)}")

    # As per https://www.w3.org/TR/vc-di-eddsa/ , Ed25519Signature2020 proof values must be multibase base58-btc values prefixed with 'z'
    proofValue = base58.b58encode(proofbytes) # encode(data=proofbytes, encoding='base64')

    #return 'z' + proofValue.decode()
    return 'z' + proofValue.decode()


def verify_proof(doc_hash, proof_hash, proof, verify_fun):
    # The hash to sign is the concatenation of the proof hash and the document hash,
    # as per https://www.w3.org/TR/vc-di-eddsa/#hashing-ed25519signature2020
    combined_hash = proof_hash + doc_hash

    proofString = proof['proofValue']

    if not proofString.startswith('z'):
        raise Exception("Ed25519Signature2020 proofValue must start with 'z'")

    # Extract signature bytes
    proofbytes = base58.b58decode(proofString[1:])

    # Verify against the hash
    verify_fun(proofbytes, combined_hash)