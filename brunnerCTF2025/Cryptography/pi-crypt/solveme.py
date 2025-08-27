from itertools import product
import string
bigrams = [
    ["th",100272945963],
    ["he",86697336727],
    ["in",68595215308],
    ["er",57754162106],
    ["an",55974567611],
    ["re",52285662239],
    ["on",49570981965],
    ["at",41920838452],
    ["en",41004903554],
    ["nd",38129777631],
    ["ti",37856196209],
    ["es",37766388079],
    ["or",35994097756],
    ["te",33973261529],
    ["of",33130341561],
    ["ed",32937140633],
    ["is",31817918249],
    ["it",31672532308],
    ["al",30662410438],
    ["ar",30308513014],
    ["st",29704461829],
    ["to",29360205581],
    ["nt",29359771944],
    ["ng",26871805511],
    ["se",26282488562],
    ["ha",26103411208],
    ["as",24561944198],
    ["ou",24531132241],
    ["io",23542263265],
    ["le",23382173640],
    ["ve",23270129573],
    ["co",22384167777],
    ["me",22360109325],
    ["de",21565300071],
    ["hi",21520845924],
    ["ri",20516398905],
    ["ro",20491179118],
    ["ic",19701195496],
    ["ne",19504235770],
    ["ea",19403941063],
    ["ra",19332539912],
    ["ce",18367773425],
    ["li",17604626629],
    ["ch",16854985236],
    ["ll",16257360474],
    ["be",16249257887],
    ["ma",15938689768],
    ["si",15509759748],
    ["om",15402602484],
    ["ur",15303657594],
    ["ca",15174413181],
    ["el",14952716079],
    ["ta",14941000711],
    ["la",14874551789],
    ["ns",14350320288],
    ["di",13899990598],
    ["fo",13753006196],
    ["ho",13672603513],
    ["pe",13477683504],
    ["ec",13457763533],
    ["pr",13378480175],
    ["no",13099447521],
    ["ct",12997849406],
    ["us",12808517567],
    ["ac",12625666388],
    ["ot",12465822481],
    ["il",12167821320],
    ["tr",12006693396],
    ["ly",11983948242],
    ["nc",11722631112],
    ["et",11634161334],
    ["ut",11423899818],
    ["ss",11421755201],
    ["so",11214705934],
    ["rs",11180732354],
    ["un",11121118166],
    ["lo",10908830081],
    ["wa",10865206430],
    ["ge",10861045622],
    ["ie",10845731320],
    ["wh",10680697684],
    ["ee",10647199443],
    ["wi",10557401491],
    ["em",10536054813],
    ["ad",10375130449],
    ["ol",10305660447],
    ["rt",10198055461],
    ["po",10189505383],
    ["we",10176141608],
    ["na",9790855551],
    ["ul",9751225781],
    ["ni",9564648232],
    ["ts",9516029773],
    ["mo",9498813191],
    ["ow",9318366591],
    ["pa",9123652775],
    ["im",8959759181],
    ["mi",8957825538],
    ["ai",8922759715],
    ["sh",8888705287],
    ["ir",8886799024],
    ["su",8774129154],
    ["id",8332214014],
    ["os",8176085241],
    ["iv",8116349309],
    ["ia",8072199471],
    ["am",8032259916],
    ["fi",8024355222],
    ["ci",7936922442],
    ["vi",7600241898],
    ["pl",7415349106],
    ["ig",7189051323],
    ["tu",7187510085],
    ["ev",7184041787],
    ["ld",7122648226],
    ["ry",6985436186],
    ["mp",6743935008],
    ["fe",6670566518],
    ["bl",6581097936],
    ["ab",6479202253],
    ["gh",6414827751],
    ["ty",6408447994],
    ["op",6313536754],
    ["wo",6252724050],
    ["sa",6147356936],
    ["ay",6128842727],
    ["ex",6035335807],
    ["ke",6027536039],
    ["fr",6011200185],
    ["oo",5928601045],
    ["av",5778409728],
    ["ag",5772552144],
    ["if",5731148470],
    ["ap",5719570727],
    ["gr",5548472398],
    ["od",5511014957],
    ["bo",5509918152],
    ["sp",5392724233],
    ["rd",5338083783],
    ["do",5307591560],
    ["uc",5291161134],
    ["bu",5214802738],
    ["ei",5169898489],
    ["ov",5021440160],
    ["by",4975814759],
    ["rm",4938158020],
    ["ep",4837800987],
    ["tt",4812693687],
    ["oc",4692062395],
    ["fa",4624241031],
    ["ef",4588497002],
    ["cu",4585165906],
    ["rn",4521640992],
    ["sc",4363410770],
    ["gi",4275639800],
    ["da",4259590348],
    ["yo",4226720021],
    ["cr",4214150542],
    ["cl",4201617719],
    ["du",4186093215],
    ["ga",4175274057],
    ["qu",4160167957],
    ["ue",4158448570],
    ["ff",4125634219],
    ["ba",4122472992],
    ["ey",4053144855],
    ["ls",3990203351],
    ["va",3946966167],
    ["um",3901923211],
    ["pp",3850125519],
    ["ua",3844138094],
    ["up",3835093459],
    ["lu",3811884104],
    ["go",3725558729],
]

# Use 200 most frequent bigrams for analysis

bigrams = [b[0] for b in bigrams[:170]]

base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789æøåÆØÅ .,!?-:()[]/{}=<>+_@^|~%$#&*`“';"

with open('unbaked_pi.txt') as f:
    pie = f.read()


def pie_crypt(text: str, key: str, i,decrypt: bool=False) -> str:
    out = ""
    j = 0

    for c in text:
        d1 = int(pie[i % len(pie)])
        i += base.index(key[j % len(key)])
        j += 1

        if j % len(key) == 0:
            i += 765 - sum(base.index(c) for c in key)

        d2 = int(pie[i % len(pie)])
        i += base.index(key[j % len(key)])
        j += 1

        shift = 10 * d1 + d2
        out += base[(base.index(c) + (-shift if decrypt else shift)) % len(base)]

        if j % len(key) == 0:
            i += 765 - sum(base.index(c) for c in key)

    return out


with open("baked_pie.txt") as f:
    ct = f.read()

def check(s: str) -> bool:
    return s.isalpha() and (s.islower() or s.isupper() or s.istitle()) and not any(c in s for c in "æøåÆØÅ")

# Try to guess starting point of i
flag = "brunner{"
for i in range(1000):
    pt = pie_crypt(ct[:4], flag, i,decrypt=True)
    if check(pt[:4]):
        print(i, pt[:10])

i0 = 765


def count_bigram(r):
    t=0
    for bg in bigrams:
        t+=r.count(bg)
    return t


for l in range(100):
    key = flag + "a"*l
    pt = pie_crypt(ct, key, decrypt=True, i=i0)
    known = [
        pt[(j * len(key) + 1) // 2:(j * len(key) + 1) // 2 + 4]
        for j in range(2 * len(pt) // len(key))
    ]
    text = " ".join(known)
    score = count_bigram(text)/len(text)
    if l==0:
        max = score
        winner = len(key)
    else :
        if score>max:
            max = score
            winner = len(key)
print("flag's length is :",winner)


for k in range((75-len(flag))//2):
    winChar = ""
    i=-1
    for char in product(base,repeat=2):

        key = flag + "".join(char) +"a"*(75-len(flag)-3) + "}"
        pt = pie_crypt(ct, key, i0,decrypt=True)
        known = [
        pt[(j * len(key) + 1) // 2:(j * len(key) + 1) // 2 + (len(flag)+2) // 2]
        for j in range(2 * len(pt) // len(key))
        ]
        t=" ".join(known)
        if any(c in t for c in "æøåÆØÅ"):
            continue
        i+=1

        test = count_bigram(t)/len(t)
        if i==0:
            max = test
            winChar = "".join(char)
        else :
            if test>max:
                max = test
                winChar = "".join(char)
    flag+=winChar
    print(flag)

# brunner{1t_W0ulD_H4v3_6een_H@rDeR_Thou9h(!),w1th_Å_k3y_Øf_Ev3n-LÆNgth.`:-7}