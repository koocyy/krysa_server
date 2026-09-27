import os
import rsa


def gen_keys():
    #private_key_pass = "631252726692175"
    #can be used later for private key encryption :)
    public_key, private_key = rsa.newkeys(1024)

    t_path = os.path.abspath(__file__)
    path = t_path.strip("\\keys.py")
    if os.path.exists(path):
        print("")
    else:
        os.mkdir("mykeys")


    with open(f"{path}/public.pem", "wb") as f:
        f.write(public_key.save_pkcs1("PEM"))

    with open(f"{path}/private.pem", "wb") as f:
        f.write(private_key.save_pkcs1("PEM"))


