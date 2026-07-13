#!/usr/bin/env python3
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
SLP=Path(__file__).resolve().parents[1] / 'baseline' / 'aes-sbox-fwd-g113-a32-d27-ad6.slp'
MASK=(1<<256)-1
@dataclass
class Op:
    kind:str; out:str; a:str; b:str|None=None

def parse():
    ops=[];inside=False
    for ln,raw in enumerate(SLP.read_text().splitlines(),1):
        s=raw.split('#',1)[0].strip()
        if s=='begin SLP':inside=True;continue
        if s=='end SLP':inside=False;continue
        if not inside or not s:continue
        p=s.split()
        if p[0] in ('XOR','XNOR','AND') and len(p)==4:ops.append(Op(*p))
        elif p[0]=='NOT' and len(p)==3:ops.append(Op(p[0],p[1],p[2],None))
        else:raise ValueError((ln,s))
    return ops

def build():
    vals={}; masks={}; andops=[]
    for i in range(8):
        vals[f'U{i}']=sum(1<<x for x in range(256) if (x>>(7-i))&1)
        masks[f'U{i}']=1<<(1+i)
    for op in parse():
        if op.kind=='XOR': vals[op.out]=vals[op.a]^vals[op.b]; masks[op.out]=masks[op.a]^masks[op.b]
        elif op.kind=='XNOR': vals[op.out]=MASK^vals[op.a]^vals[op.b]; masks[op.out]=1^masks[op.a]^masks[op.b]
        elif op.kind=='NOT': vals[op.out]=MASK^vals[op.a]; masks[op.out]=1^masks[op.a]
        else:
            vals[op.out]=vals[op.a]&vals[op.b];andops.append(op);masks[op.out]=1<<(8+len(andops))
    return vals,masks,andops

def rank(vs):
    b={}
    for z in vs:
        x=z
        while x:
            p=x.bit_length()-1
            if p in b:x^=b[p]
            else:b[p]=x;break
    return len(b)

def solve_coords(v,vs):
    b={}
    for i,z in enumerate(vs):
        x=z;c=1<<i
        while x:
            p=x.bit_length()-1
            if p in b:x^=b[p][0];c^=b[p][1]
            else:b[p]=(x,c);break
    x=v;c=0
    while x:
        p=x.bit_length()-1
        if p not in b:return None
        x^=b[p][0];c^=b[p][1]
    return c
pairs=list(combinations(range(12),2)); pairidx={p:i for i,p in enumerate(pairs)}
def wedge(u,v):
    z=0
    for i,j in pairs:
        if (((u>>i)&1)&((v>>j)&1)) ^ (((u>>j)&1)&((v>>i)&1)):z|=1<<pairidx[i,j]
    return z

def independent_ordered(xs):
    b={};out=[]
    for z in xs:
        x=z
        while x:
            p=x.bit_length()-1
            if p in b:x^=b[p]
            else:b[p]=x;out.append(z);break
    return out

def derive():
    vals,masks,andops=build();assert len(andops)==32
    L=[vals[x] for x in ['t8','t11','t2','t10']]
    R=[vals[x] for x in ['t13','t15','t21','t6']]
    Z=[vals[x] for x in ['t66','t59','t65','t62']]
    def coord(name,basis,shift):
        c=solve_coords(vals[name],basis);assert c is not None,(name,shift);return c<<shift
    P=[]
    for i in range(9):P.append(wedge(coord(andops[i].a,L,0),coord(andops[i].b,R,4)))
    for i in range(14,23):P.append(wedge(coord(andops[i].a,Z,8),coord(andops[i].b,R,4)))
    for i in range(23,32):P.append(wedge(coord(andops[i].a,Z,8),coord(andops[i].b,L,0)))
    assert rank(P)==27
    prodidx=list(range(1,10))+list(range(15,33))
    def prodcoeff(mask):
        c=0
        for j,aidx in enumerate(prodidx):
            if (mask>>(8+aidx))&1:c|=1<<j
        return c
    pre=[]
    for op in andops[9:14]:pre.extend([prodcoeff(masks[op.a]),prodcoeff(masks[op.b])])
    allr=pre+[prodcoeff(masks[f'S{i}']) for i in range(8)]
    pc=independent_ordered(pre);ac=independent_ordered(allr)
    def mapform(c):
        z=0
        for j,p in enumerate(P):
            if c>>j&1:z^=p
        return z
    Qpre=[mapform(c) for c in pc];Q=[mapform(c) for c in ac]
    print('ranks',rank(P),rank(Qpre),rank(Q))
    print('Qpre',*[f'{x:x}' for x in Qpre])
    print('Q',*[f'{x:x}' for x in Q])
    return vals,masks,andops,L,R,Z,P,Qpre,Q,pc,ac
if __name__=='__main__':derive()
