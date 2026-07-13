#!/usr/bin/env python3
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from collections import Counter
from itertools import combinations

ROOT=Path(__file__).resolve().parents[1]
NIST=ROOT / 'baseline' / 'aes-sbox-fwd-g113-a32-d27-ad6.slp'
CERT=ROOT / 'certificates' / 'tower24_witness.txt'
STAGED=ROOT / 'certificates' / 'staged29_witness.txt'
OUT=ROOT / 'circuits' / 'aes-sbox-fwd-g455-a29-d35-ad6-transparent.slp'
MASK=(1<<256)-1

@dataclass
class Op:
    kind:str; out:str; a:str; b:str|None=None

def parse_nist():
    ops=[];inside=False
    for ln,raw in enumerate(NIST.read_text().splitlines(),1):
        s=raw.split('#',1)[0].strip()
        if s=='begin SLP':inside=True;continue
        if s=='end SLP':inside=False;continue
        if not inside or not s:continue
        p=s.split()
        if p[0] in ('XOR','XNOR','AND') and len(p)==4:ops.append(Op(*p))
        elif p[0]=='NOT' and len(p)==3:ops.append(Op(p[0],p[1],p[2],None))
        else:raise ValueError((ln,s))
    return ops

def eval_nist():
    vals={}
    for i in range(8):vals[f'U{i}']=sum(1<<x for x in range(256) if (x>>(7-i))&1)
    andops=[]
    for op in parse_nist():
        if op.kind=='XOR':vals[op.out]=vals[op.a]^vals[op.b]
        elif op.kind=='XNOR':vals[op.out]=MASK^vals[op.a]^vals[op.b]
        elif op.kind=='NOT':vals[op.out]=MASK^vals[op.a]
        else:vals[op.out]=vals[op.a]&vals[op.b];andops.append(op)
    return vals,andops

def parse_cert():
    lines=[x.strip() for x in CERT.read_text().splitlines() if x.strip()]
    if not lines[0].startswith('A '):raise ValueError('bad cert')
    A=int(lines[0].split()[1],16)
    products=[];i=1
    while lines[i]!='COEFF':
        u,v,q=(int(x,16) for x in lines[i].split());products.append((u,v,q));i+=1
    coeff=[int(x,16) for x in lines[i+1:]]
    assert len(products)==24 and len(coeff)==12
    return A,products,coeff

def parse_staged():
    lines=[x.split('#',1)[0].strip() for x in STAGED.read_text().splitlines()]
    lines=[x for x in lines if x]
    assert lines[0]=='AES29-STAGED 1'
    i=1;coords=[]
    for name in [f'L{j}' for j in range(4)]+[f'R{j}' for j in range(4)]:
        p=lines[i].split();assert p[:2]==['COORD',name] and len(p)==3
        coords.append(int(p[2],16));i+=1
    p=lines[i].split();assert p[0]=='EARLY';early=p[1:];i+=1
    middle=[]
    for j in range(1,6):
        p=lines[i].split();assert p[:2]==['MIDDLE',f'M{j}'] and len(p)==4
        middle.append((int(p[2],16),int(p[3],16)));i+=1
    post=[]
    for j in range(4):
        p=lines[i].split();assert p[:2]==['POST',f'Z{j}'] and len(p)==3
        post.append(int(p[2],16));i+=1
    p=lines[i].split();assert p[0]=='LATE';late=p[1:];i+=1
    outputs=[]
    for j in range(8):
        p=lines[i].split();assert p[:2]==['OUTPUT',f'S{j}'] and len(p)==3
        outputs.append(int(p[2],16));i+=1
    assert lines[i]=='END' and i+1==len(lines)
    return coords,early,middle,post,late,outputs

def main():
    vals,andops=eval_nist();assert len(andops)==32
    A,products,_=parse_cert()
    coordinate_masks,early_labels,middle_masks,post_masks,late_labels,output_masks=parse_staged()
    coord_names=['t8','t11','t2','t10','t13','t15','t21','t6','t66','t59','t65','t62']
    coord_vals=[vals[x] for x in coord_names]
    early_idx=[i for i,(u,v,q) in enumerate(products) if (u|v)<(1<<8)]
    late_idx=[i for i in range(24) if i not in early_idx]
    assert early_idx==[0,1,2,8,9,10,16,17,18] and len(late_idx)==15
    assert early_labels==[f'P{i+1:02d}' for i in early_idx]
    assert late_labels==[f'P{i+1:02d}' for i in late_idx]
    for mask,name in zip(coordinate_masks,coord_names[:8]):
        reconstructed=0
        for i in range(8):
            if mask>>i&1:reconstructed^=vals[f'U{i}']
        assert reconstructed==vals[name],(name,hex(mask))

    # Start with the NIST input-linear layer t1..t23 (all XOR).
    lines=[]
    for op in parse_nist():
        if op.out=='t24':break
        assert op.kind=='XOR'
        lines.append(f'XOR {op.out} {op.a} {op.b}')
    assert lines[-1].split()[1]=='t23' and len(lines)==23
    next_t=24
    def fresh():
        nonlocal next_t
        z=f't{next_t}';next_t+=1;return z

    zero=None;one=None
    def get_zero():
        nonlocal zero
        if zero is None:
            zero=fresh();lines.append(f'XOR {zero} U0 U0')
        return zero
    def get_one():
        nonlocal one
        if one is None:
            one=fresh();lines.append(f'NOT {one} {get_zero()}')
        return one
    def xor_list(wires,target=None):
        if not wires:
            z=get_zero()
            if target is None:return z
            lines.append(f'XOR {target} {z} {z}');return target
        if len(wires)==1:
            if target is None:return wires[0]
            lines.append(f'XOR {target} {wires[0]} {get_zero()}');return target
        cur=wires[0]
        for j,w in enumerate(wires[1:]):
            out=target if target is not None and j==len(wires)-2 else fresh()
            lines.append(f'XOR {out} {cur} {w}');cur=out
        return cur

    # Cache coordinate forms; L/R are already available, Z later.
    form_cache={1<<i:coord_names[i] for i in range(8)}
    def coord_form(mask,available=12):
        if mask in form_cache:return form_cache[mask]
        if mask>>available:raise ValueError(('unavailable coordinate',hex(mask),available))
        ws=[coord_names[i] for i in range(available) if mask>>i&1]
        z=xor_list(ws);form_cache[mask]=z;return z

    product_names=[None]*24;product_vals=[None]*24
    def product_value(u,v):
        a=b=0
        for i,x in enumerate(coord_vals):
            if u>>i&1:a^=x
            if v>>i&1:b^=x
        return a&b

    # Materialize nine early products.
    for idx in early_idx:
        u,v,_=products[idx]
        a=coord_form(u,8);b=coord_form(v,8);o=fresh();lines.append(f'AND {o} {a} {b}')
        product_names[idx]=o;product_vals[idx]=product_value(u,v)

    input_names=[f'U{i}' for i in range(8)]
    input_vals=[vals[x] for x in input_names]
    early_names=[product_names[i] for i in early_idx]
    early_vals=[product_vals[i] for i in early_idx]
    middle_names=[];middle_vals=[]

    # Reconstruct and compute the five NIST middle ANDs from the fixed staged witness.
    for midx,(op,factor_masks) in enumerate(zip(andops[9:14],middle_masks),1):
        basis_vals=[MASK]+input_vals+early_vals+middle_vals
        basis_names=['$ONE']+input_names+early_names+middle_names
        factor_wires=[]
        for c,target in zip(factor_masks,(vals[op.a],vals[op.b])):
            assert c < (1<<len(basis_names)),(midx,hex(c),len(basis_names))
            reconstructed=0
            for j,value in enumerate(basis_vals):
                if c>>j&1:reconstructed^=value
            assert reconstructed==target,(midx,op,hex(c))
            ws=[basis_names[j] for j in range(1,len(basis_names)) if c>>j&1]
            if c&1:
                if ws:
                    t=xor_list(ws);o=fresh();lines.append(f'NOT {o} {t}');factor_wires.append(o)
                else:factor_wires.append(get_one())
            else:factor_wires.append(xor_list(ws))
        out=fresh();lines.append(f'AND {out} {factor_wires[0]} {factor_wires[1]}')
        middle_names.append(out);middle_vals.append(vals[op.out])
        # independent truth-table sanity for the new AND
        assert vals[op.a]&vals[op.b]==vals[op.out]

    # Reconstruct Z coordinate wires from the fixed staged witness.
    base_vals=[MASK]+input_vals+early_vals+middle_vals
    base_names=['$ONE']+input_names+early_names+middle_names
    for zi,c in zip(range(8,12),post_masks):
        assert c < (1<<len(base_names))
        reconstructed=0
        for j,value in enumerate(base_vals):
            if c>>j&1:reconstructed^=value
        assert reconstructed==coord_vals[zi],(zi,hex(c))
        ws=[base_names[j] for j in range(1,len(base_names)) if c>>j&1]
        if c&1:
            t=xor_list(ws);o=fresh();lines.append(f'NOT {o} {t}')
        else:o=xor_list(ws)
        coord_names[zi]=o;form_cache[1<<zi]=o

    # Materialize fifteen late products.
    for idx in late_idx:
        u,v,_=products[idx]
        a=coord_form(u,12);b=coord_form(v,12);o=fresh();lines.append(f'AND {o} {a} {b}')
        product_names[idx]=o;product_vals[idx]=product_value(u,v)

    # Reconstruct all outputs from the fixed staged witness.
    final_vals=[MASK]+input_vals+early_vals+middle_vals+[product_vals[i] for i in late_idx]
    final_names=['$ONE']+input_names+early_names+middle_names+[product_names[i] for i in late_idx]
    for oi,c in enumerate(output_masks):
        assert c < (1<<len(final_names))
        reconstructed=0
        for j,value in enumerate(final_vals):
            if c>>j&1:reconstructed^=value
        assert reconstructed==vals[f'S{oi}'],(oi,hex(c))
        ws=[final_names[j] for j in range(1,len(final_names)) if c>>j&1]
        if c&1:
            t=xor_list(ws);lines.append(f'NOT S{oi} {t}')
        else:xor_list(ws,target=f'S{oi}')

    # Structural tally/depth.
    counts=Counter();depth={f'U{i}':0 for i in range(8)};adepth=dict(depth)
    seen=set(depth)
    for line in lines:
        p=line.split();kind,out,args=p[0],p[1],p[2:]
        assert out not in seen and all(a in seen for a in args),(line,[a for a in args if a not in seen])
        seen.add(out);counts[kind]+=1
        depth[out]=1+max(depth[a] for a in args)
        adepth[out]=max(adepth[a] for a in args)+(1 if kind=='AND' else 0)
    assert counts['AND']==29 and all(f'S{i}' in seen for i in range(8))
    total=len(lines);d=max(depth[f'S{i}'] for i in range(8));ad=max(adepth[f'S{i}'] for i in range(8));internal=next_t-1
    header=f'''# Transparent 29-AND straight-line program for the forward AES S-box.
# U0 and S0 are the most significant bits.
# Tally: 8 inputs, 8 outputs, {total} gates, {counts['AND']} AND, {counts['XOR']} XOR, {counts['NOT']} NOT
# Depth(Gate): {d}; Depth(AND): {ad}

begin circuit AES-SBOX-FWD-A29-TRANSPARENT
Inputs: U0:U7
Outputs: S0:S7
Internal: t1:t{internal}
GateSyntax: GateName Output Inputs
begin SLP
'''
    OUT.write_text(header+'\n'.join(lines)+'\nend SLP\nend circuit\n')
    print('wrote',OUT)
    print('transform',hex(A),'early',early_idx,'late',late_idx)
    print('tally',counts,'total',total,'depth',d,'and-depth',ad,'internal',internal)

if __name__=='__main__':main()
