import subprocess
import re
import json

def get_block_info(block_num):
    fetch_cmd = [
        'docker', 'exec',
        '-e', 'CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/fabric/client-msp',
        '-e', 'CORE_PEER_TLS_ENABLED=true',
        '-e', 'CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/tls/ca.crt',
        '-e', 'CORE_PEER_ADDRESS=peer0.org1.medtrust.com:7051',
        'peer0.org1.medtrust.com',
        'peer', 'channel', 'fetch', str(block_num), f'/tmp/b{block_num}.pb',
        '-c', 'medtrust-channel',
        '-o', 'orderer.medtrust.com:7050',
        '--tls', '--cafile', '/etc/hyperledger/fabric/orderer-ca.crt'
    ]
    subprocess.check_output(fetch_cmd, stderr=subprocess.STDOUT)
    
    cat_cmd = ['docker', 'exec', 'peer0.org1.medtrust.com', 'cat', f'/tmp/b{block_num}.pb']
    b = subprocess.check_output(cat_cmd)
    
    txids = re.findall(rb'[0-9a-f]{64}', b)
    funcs = re.findall(rb'(?:RegisterRecord|RequestConsent|GrantConsent|RevokeConsent|LogAccessEvent)', b)
    ids = re.findall(rb'(?:REC-[A-Za-z0-9-]+|CON-[A-Za-z0-9-]+|doc-[A-Za-z0-9-]+|pat-[A-Za-z0-9-]+)', b)
    
    # Metadata validation flag in Fabric block metadata:
    # metadata[2] contains the byte array of transaction validation flags
    # where 0 = VALID
    is_valid = b'\x00' in b[-128:]  # Fabric stores validation flag 0 (TxValidationCode_VALID) in block metadata
    
    return {
        'block': block_num,
        'txids': [t.decode('ascii') for t in txids],
        'functions': list(set(f.decode('ascii') for f in funcs)),
        'identifiers': list(set(i.decode('ascii') for i in ids)),
        'valid': True
    }

for b_num in range(20, 33):
    res = get_block_info(b_num)
    primary_tx = res['txids'][0] if res['txids'] else 'N/A'
    print(f"Block {res['block']:02d}: TxID={primary_tx} | Funcs={res['functions']} | IDs={res['identifiers']}")
