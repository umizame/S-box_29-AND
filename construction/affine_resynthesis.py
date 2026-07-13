#!/usr/bin/env python3
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from collections import Counter,defaultdict

ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT / 'circuits' / 'aes-sbox-fwd-g455-a29-d35-ad6-transparent.slp'
DST=ROOT / 'circuits' / 'aes-sbox-fwd-g228-a29-d35-ad6.slp'
INPUTS=[f'U{i}' for i in range(8)];OUTPUTS=[f'S{i}' for i in range(8)]
@dataclass
class Gate:
    op:str;out:str;args:list[str]

def parse():
    ops=[];inside=False
    for raw in SRC.read_text().splitlines():
        s=raw.split('#',1)[0].strip()
        if s=='begin SLP':inside=True;continue
        if s=='end SLP':inside=False;continue
        if inside and s:
            p=s.split();ops.append(Gate(p[0],p[1],p[2:]))
    return ops

def masks_of(ops):
    m={x:1<<(1+i) for i,x in enumerate(INPUTS)};ai=0
    for g in ops:
        if g.op=='XOR':m[g.out]=m[g.args[0]]^m[g.args[1]]
        elif g.op=='NOT':m[g.out]=m[g.args[0]]^1
        elif g.op=='AND':ai+=1;m[g.out]=1<<(8+ai)
        else:raise ValueError(g)
    return m

def resolve(alias,x):
    path=[]
    while alias.get(x,x)!=x:path.append(x);x=alias[x]
    for y in path:alias[y]=x
    return x

def alias_identical(ops, roots=None):
    masks=masks_of(ops);alias={x:x for x in INPUTS};rep={masks[x]:x for x in INPUTS};out=[]
    for g in ops:
        args=[resolve(alias,a) for a in g.args]
        if g.op!='AND' and masks[g.out] in rep:
            alias[g.out]=rep[masks[g.out]]
        else:
            alias[g.out]=g.out;out.append(Gate(g.op,g.out,args));rep.setdefault(masks[g.out],g.out)
    if roots is None:roots={o:o for o in OUTPUTS}
    roots={o:resolve(alias,roots[o]) for o in OUTPUTS}
    return out,roots

def dce(ops,roots):
    by={g.out:g for g in ops};need=set(roots.values());stack=list(need)
    while stack:
        x=stack.pop();g=by.get(x)
        if g:
            for a in g.args:
                if a not in need:need.add(a);stack.append(a)
    return [g for g in ops if g.out in need]

def count(ops):return Counter(g.op for g in ops)

def optimize():
    ops,roots=alias_identical(parse());ops=dce(ops,roots)
    print('start',len(ops),count(ops),roots,flush=True)
    iteration=0
    while True:
        iteration+=1;masks=masks_of(ops);pos={g.out:i for i,g in enumerate(ops)}
        earlier=list(INPUTS);by_mask=defaultdict(list)
        for x in earlier:by_mask[masks[x]].append(x)
        best=None
        for gi,g in enumerate(ops):
            target=masks[g.out]
            if g.op!='AND':
                candidates=[];seen=set()
                for a in earlier:
                    want=target^masks[a]
                    for b in by_mask.get(want,[]):
                        if a==b:continue
                        pair=tuple(sorted((a,b)))
                        if pair not in seen:seen.add(pair);candidates.append(('XOR',list(pair)))
                for a in by_mask.get(target^1,[]):candidates.append(('NOT',[a]))
                for op,args in candidates:
                    if op==g.op and ((op=='NOT' and args==g.args) or (op=='XOR' and set(args)==set(g.args))):continue
                    test=[Gate(x.op,x.out,list(x.args)) for x in ops];test[gi]=Gate(op,g.out,args)
                    live=dce(test,roots);gain=len(ops)-len(live)
                    if gain<=0:continue
                    ac=count(live)['AND']
                    # all 29 ANDs should stay; reject anything else to preserve same construction
                    if ac!=29:continue
                    mx=max((-1 if a in INPUTS else pos.get(a,-1)) for a in args)
                    score=(gain,-mx)
                    if best is None or score>best[0]:best=(score,gi,op,args,g)
            earlier.append(g.out);by_mask[masks[g.out]].append(g.out)
        if best is None:break
        score,gi,op,args,g=best
        print('iter',iteration,'gain',score[0],g.out,g.op,g.args,'->',op,args,flush=True)
        for x in ops:
            if x.out==g.out:x.op=op;x.args=args;break
        ops=dce(ops,roots)
        ops,roots=alias_identical(ops,roots);ops=dce(ops,roots)
    print('final',len(ops),count(ops),roots,flush=True)
    return ops,roots

def verify_formal(original,newops,newroots):
    om=masks_of(original);nm=masks_of(newops)
    # New AND atom ordering must correspond exactly to original surviving order.
    origands=[g for g in original if g.op=='AND'];newands=[g for g in newops if g.op=='AND']
    assert len(origands)==len(newands)==29
    # Compute original factor masks per AND in original atom convention.
    for a,b in zip(origands,newands):
        assert a.out==b.out,(a.out,b.out)
        assert om[a.args[0]]==nm[b.args[0]],(a.out,'left')
        assert om[a.args[1]]==nm[b.args[1]],(a.out,'right')
    for o in OUTPUTS:assert om[o]==nm[newroots[o]],o

def emit(ops,roots):
    mapping={x:x for x in INPUTS};lines=[];n=0
    def fresh():
        nonlocal n;n+=1;return f't{n}'
    for g in ops:
        args=[mapping[a] for a in g.args]
        if g.out in OUTPUTS and roots.get(g.out,g.out)==g.out:out=g.out
        else:out=fresh()
        mapping[g.out]=out;lines.append(f'{g.op} {out} '+' '.join(args))
    zero=None
    for o in OUTPUTS:
        r=roots[o];src=mapping[r]
        if src==o:continue
        if zero is None:zero=fresh();lines.append(f'XOR {zero} U0 U0')
        lines.append(f'XOR {o} {src} {zero}')
    dep={x:0 for x in INPUTS};ad=dict(dep);cnt=Counter();seen=set(INPUTS)
    for s in lines:
        p=s.split();op,out,args=p[0],p[1],p[2:]
        assert out not in seen and all(a in seen for a in args),s
        seen.add(out);cnt[op]+=1
        dep[out]=1+max(dep[x] for x in args);ad[out]=max(ad[x] for x in args)+(op=='AND')
    total=len(lines);d=max(dep[o] for o in OUTPUTS);dd=max(ad[o] for o in OUTPUTS)
    hdr=f'''# Affine-resynthesized 29-AND straight-line program for the forward AES S-box.
# U0 and S0 are the most significant bits.
# Tally: 8 inputs, 8 outputs, {total} gates, {cnt['AND']} AND, {cnt['XOR']} XOR, {cnt['NOT']} NOT
# Depth(Gate): {d}; Depth(AND): {dd}

begin circuit AES-SBOX-FWD-A29-OPT
Inputs: U0:U7
Outputs: S0:S7
Internal: t1:t{n}
GateSyntax: GateName Output Inputs
begin SLP
'''
    DST.write_text(hdr+'\n'.join(lines)+'\nend SLP\nend circuit\n')
    print('wrote',DST,'count',cnt,'total',total,'depth',d,'AD',dd,flush=True)

if __name__=='__main__':
    original=parse();ops,roots=optimize();verify_formal(original,ops,roots);emit(ops,roots)
