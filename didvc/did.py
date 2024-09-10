import requests, didkit, json

DID_UNIRESOLVER = "https://dev.uniresolver.io/1.0/identifiers/"
DID_INDYRESOLVER = "https://indy.ogc.secd.eu/resolver/resolve/"

async def resolve(did):
    # If sovrin method, first try our custom Indy resolver
    if did.startswith('did:sov'):
        try:
            return resolveIndy(did)
        except:
            pass

    # Fall back to didkit
    try:
        return json.loads(await didkit.resolve_did(did, "{}"))
    except Exception as err:
        print ("DIDkit failed, falling back to uniresolver: "+str(err))
        pass

    # Fall back to uniresolver
    return resolveuniresolver(did)

def resolveuniresolver(did):
    response = requests.get( DID_UNIRESOLVER + did,
                             verify=True,
                             headers={ 'Accept': 'application/json' })
    if response.ok :
        return json.loads(response.text)
    else:
        raise Exception(f"Uniresolver failed : [{response.status_code}] {response.text}")

def resolveIndy(did):
    response = requests.get( DID_INDYRESOLVER + did,
                             verify=True,
                             headers={ 'Accept': 'application/json' })

    data = json.loads(response.text)
    return data['did_document']