# **redpwnCTF 2020**

<p align="center">
	<img width=150 src="assets//images//logo_1.png">
</p>

This is my writeup for the challenges in redpwnCTF 2020.



# Table of Contents

* [Miscellaneous](#miscellaneous)

  * [sanity-check](#sanity-check)
  * [discord](#discord)
  * [uglybash](#uglybash)

* [Cryptography](#cryptography)

  * [base646464](#base646464)
  * [pseudo-key](#pseudo-key)
  * [4k-rsa](#4k-rsa)

* [Web](#web)

  * [inspector-general](#inspector-general)
  * [login](#login)
  * [static-pastebin](#static-pastebin)

* [Reversing](#reversing)

  * [ropes](#ropes)
  * [bubbly](#bubbly)

* [Pwn](#pwn)

  * [coffer-overflow-1](#coffer-overflow-1)

  

#  Miscellaneous

## sanity-check

Good luck; have fun! `flag{54n1ty_ch3ck_f1r5t_bl00d?}`

**`flag{54n1ty_ch3ck_f1r5t_bl00d?}`**

**Solution:** This is by far the most difficult challenge in the CTF and requested me to use complex and advanced techniques in order to get the flag, unfortunately this writeup is to short to contain the entire solution.

**Resources:**

* Fermat's last theorem: [https://en.wikipedia.org/wiki/Fermat%27s_Last_Theorem#Fermat's_conjecture](https://en.wikipedia.org/wiki/Fermat's_Last_Theorem#Fermat's_conjecture)

## discord

Join our discord: https://discord.gg/25fu2Xd. Flag is in #announcements

**`flag{w3lc0me_t0_r3dpwnctf_d1sc0rd}`**

**Solution:** This challenge was very guessy and I don't know how the authors expected us to solve this, the flag is actually in the #announcement channel in the discord server.

## uglybash

This bash script evaluates to `echo dont just run it, dummy \# flag{...}` where the flag is in the comments.

The comment won't be visible if you just execute the script. How can you mess with bash to get the value right before it executes?

Enjoy the intro misc chal.

**`flag{us3_zsh,_dummy}`**

**Solution:** use bash -x to see commands executed  

`bash -x cmd.sh 2>&1 | grep "printf %s" | cut -d " " -f 4 | tr -d "\n" | sed "s/'/ /g"` 



# Cryptography

## base646464

Encoding something multiple times makes it exponentially more secure!

**`flag{l00ks_l1ke_a_l0t_of_64s}`**

**Solution:** 

```javascript
const atob = str => Buffer.from(str, 'base64').toString('ascii');

const fs = require("fs");
const flag = fs.readFileSync("cipher.txt", "utf8").trim();

let ret = flag;
for(let i = 0; i < 25; i++) ret = atob(ret);

fs.writeFileSync("flag.txt", ret);
```



## pseudo-key


Keys are not always as they seem...

**Note:** Make sure to wrap the plaintext with `flag{}` before you submit!

**`flag{i_guess_pseudo_keys_are_pseudo_secure}`**

**Solution:** more reverse than crypto use all possible keys and guess word

```python
#!/usr/bin/env python3

from string import ascii_lowercase
from itertools import product
predicted = ""

chr_to_num = {c: i for i, c in enumerate(ascii_lowercase)}
num_to_chr = {i: c for i, c in enumerate(ascii_lowercase)}

def decrypt_key(ctxt):
    ptxt = []
    for i in range(len(ctxt)):
        if ctxt[i] == '_':
            ctxt += '_'
            continue
        x = chr_to_num[ctxt[i]]
        ptxt += [[num_to_chr[(x // 2) % 26],num_to_chr[((x + 26) // 2) % 26]]]
    return ptxt

def decrypt(ctxt, key):
    key = ''.join(key[i % len(key)] for i in range(len(ctxt))).lower()
    ptxt = ''
    for i in range(len(ctxt)):
        if ctxt[i] == '_':
            ptxt += '_'
            continue
        x = chr_to_num[ctxt[i]]
        y = chr_to_num[key[i]]
        ptxt += num_to_chr[(x - y) % 26]
    if predicted in ptxt:
        return ptxt
    else:
        return ''

ctxt = "z_jjaoo_rljlhr_gauf_twv_shaqzb_ljtyut"
pseudo_key = "iigesssaemk"


perms_key = decrypt_key(pseudo_key)
key_possiblities = [''.join(perm) for perm in product(*perms_key)]
plaintexts = [(key,decrypt(ctxt,key)) for key in key_possiblities]
plaintexts = [(c[0], "flag{{{}}}".format(c[1])) for c in plaintexts if c[1] != '']
plaintexts.sort()
print(plaintexts)
print('Ciphertext:',ctxt)
print('Pseudo-key:',pseudo_key)

```

## 4k-rsa

**`flag{t0000_m4nyyyy_pr1m355555}`**

```python
from Crypto.Util.number import long_to_bytes, inverse

n = 5028492424316659784848610571868499830635784588253436599431884204425304126574506051458282629520844349077718907065343861952658055912723193332988900049704385076586516440137002407618568563003151764276775720948938528351773075093802636408325577864234115127871390168096496816499360494036227508350983216047669122408034583867561383118909895952974973292619495653073541886055538702432092425858482003930575665792421982301721054750712657799039327522613062264704797422340254020326514065801221180376851065029216809710795296030568379075073865984532498070572310229403940699763425130520414160563102491810814915288755251220179858773367510455580835421154668619370583787024315600566549750956030977653030065606416521363336014610142446739352985652335981500656145027999377047563266566792989553932335258615049158885853966867137798471757467768769820421797075336546511982769835420524203920252434351263053140580327108189404503020910499228438500946012560331269890809392427093030932508389051070445428793625564099729529982492671019322403728879286539821165627370580739998221464217677185178817064155665872550466352067822943073454133105879256544996546945106521271564937390984619840428052621074566596529317714264401833493628083147272364024196348602285804117877
e = 65537
c = 3832859959626457027225709485375429656323178255126603075378663780948519393653566439532625900633433079271626752658882846798954519528892785678004898021308530304423348642816494504358742617536632005629162742485616912893249757928177819654147103963601401967984760746606313579479677305115496544265504651189209247851288266375913337224758155404252271964193376588771249685826128994580590505359435624950249807274946356672459398383788496965366601700031989073183091240557732312196619073008044278694422846488276936308964833729880247375177623028647353720525241938501891398515151145843765402243620785039625653437188509517271172952425644502621053148500664229099057389473617140142440892790010206026311228529465208203622927292280981837484316872937109663262395217006401614037278579063175500228717845448302693565927904414274956989419660185597039288048513697701561336476305496225188756278588808894723873597304279725821713301598203214138796642705887647813388102769640891356064278925539661743499697835930523006188666242622981619269625586780392541257657243483709067962183896469871277059132186393541650668579736405549322908665664807483683884964791989381083279779609467287234180135259393984011170607244611693425554675508988981095977187966503676074747171
primes = [9353689450544968301, 9431486459129385713, 9563871376496945939, 9734621099746950389, 9736426554597289187, 10035211751896066517, 10040518276351167659, 10181432127731860643, 10207091564737615283, 10435329529687076341, 10498390163702844413, 10795203922067072869, 11172074163972443279, 11177660664692929397, 11485099149552071347, 11964233629849590781, 11992188644420662609, 12084363952563914161, 12264277362666379411, 12284357139600907033, 13115347801685269351, 13330028326583914849, 13447718068162387333, 13554661643603143669, 13558122110214876367, 13579057804448354623, 13716062103239551021, 13789440402687036193, 13856162412093479449, 13857614679626144761, 14296909550165083981, 14302754311314161101, 14636284106789671351, 14893589315557698913, 15067220807972526163, 15241351646164982941, 15407706505172751449, 15524931816063806341, 15525253577632484267, 15549005882626828981, 15687871802768704433, 15720375559558820789, 15734713257994215871, 15742065469952258753, 15861836139507191959, 16154675571631982029, 16175693991682950929, 16418126406213832189, 16568399117655835211, 16663643217910267123, 16750888032920189263, 16796967566363355967, 16842398522466619901, 17472599467110501143, 17616950931512191043, 17825248785173311981, 18268960885156297373, 18311624754015021467, 18415126952549973977, 16618761350345493811, 16136191597900016651, 14764546515788021591, 12726850839407946047, 11616532426455948319]

phi = 1
for p in primes:
  phi *= (int(p) - 1)
d = inverse(e,phi)
plain = pow(c,d,n)
print(long_to_bytes(plain))

```



# Web

## inspector-general

**`flag{1nspector_g3n3ral_at_w0rk}`**

**Solution:** in the metadata for the index page

## login

**`flag{0bl1g4t0ry_5ql1}`**

**Solution:** sqli on password field

## static-pastebin

**`flag{54n1t1z4t10n_k1nd4_h4rd}`**

**Solutions:** reflacted xss 

# Reversing

## ropes

**`flag{r0pes_ar3_just_l0ng_str1ngs}`**

**Solution:** run strings

## bubbly

**`flag{4ft3r_y0u_put_u54c0_0n_y0ur_c011ege_4pp5_y0u_5t1ll_h4ve_t0_d0_th15_57uff}`**

**Solution:** bubble sort 

`echo 1 2 3 4 5 6 7 8 5 6 7 6 6 7 4 5 6 1 4 3 7 6 5 10 | nc 2020.redpwnc.tf 31039`

# Pwn

## coffer-overflow-1

**`flag{b0ffer_0verf10w_3asy_as_123}`**

**Solution:** Buffer Overflow







