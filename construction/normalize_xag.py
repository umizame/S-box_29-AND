#!/usr/bin/env python3
from pathlib import Path
import sys

def parse(path):
    ops=[];inside=False
    for ln,raw in enumerate(Path(path).read_text().splitlines(),1):
        s=raw.split('#',1)[0].strip()
        if s=='begin SLP':inside=True;continue
        if s=='end SLP':inside=False;continue
        if inside and s:
            p=s.split()
            if p[0] in ('XOR','AND') and len(p)==4:ops.append((p[0],p[1],p[2],p[3]))
            elif p[0]=='NOT' and len(p)==3:ops.append((p[0],p[1],p[2]))
            else:raise ValueError((ln,s))
    return ops

def norm(path):
    m={f'U{i}':1<<(1+i) for i in range(8)};g=[]
    for p in parse(path):
        k,o,*a=p
        if k=='XOR':m[o]=m[a[0]]^m[a[1]]
        elif k=='NOT':m[o]=m[a[0]]^1
        else:
            g.append((m[a[0]],m[a[1]]));m[o]=1<<(8+len(g))
    return g,[m[f'S{i}'] for i in range(8)]
if __name__=='__main__':
    g,o=norm(sys.argv[1]);print('AES29-XAG 1');print('AND_COUNT',len(g))
    for i,(a,b) in enumerate(g,1):print(f'AND A{i:02d} {a:x} {b:x}')
    print('OUTPUT_COUNT 8')
    for i,x in enumerate(o):print(f'OUTPUT S{i} {x:x}')
    print('END')
