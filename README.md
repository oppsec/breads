<div align="center">
<img src="https://i.imgur.com/xV6HY67.jpeg">

<h3> 🍞 BREADS (Breaking Active Directory Security) </h3>
<br>

___

<img src="https://img.shields.io/github/license/oppsec/breads?color=blue&logo=github&style=for-the-badge">
<img src="https://img.shields.io/github/issues/oppsec/breads?color=blue&logo=github&style=for-the-badge">
<img src="https://img.shields.io/github/stars/oppsec/breads?color=blue&logo=github&style=for-the-badge">
<img src="https://img.shields.io/github/forks/oppsec/breads?color=blue&logo=github&style=for-the-badge">
<img src="https://img.shields.io/github/languages/code-size/oppsec/breads?color=blue&logo=github&style=for-the-badge">

</div>

<h3> What is Breads? </h3>
<p> <b>BREADS</b> is a tool focused on enumerating and attacking Active Directory environments through LDAP, SMB, and other protocols (not done yet). This project is inspired by other existing tools like CrackMapExec and NetExec. </p>

<br>

<h3> Why use this? </h3>
<p> This project is created and maintained by security researchers who want to study and discover more about Active Directory environments, then you don't need to use this necessary but I promise the team is trying its best to make this a usable tool and a cool project </p>

<br>

<h3> Any advantage? </h3>
<p> Yes, the principal Breads advantages are the flexibility of creating profiles that are directly stored on the local machine (through the .breads directory created on the user's home) and the easy way to execute commands without needing to re-type the same credentials every time. I like how the 'whoami' command works and that's all. </p>

<br>

<h3> Installation </h3>
<pre>
~$ apt install pipx
~$ pipx ensurepath
~$ pipx install git+https://github.com/oppsec/breads.git
~$ breads-ad
</pre>

If you encounter any error when trying to install you might use --break-system-packages flag

<br>

<h3> Preview </h3>
<img src="https://i.imgur.com/DMBGUqh.png">

<h3> Credits </h3>
<ul>
    <li>CrackMapExec</li>
    <li>Impacket</li>
    <li>NetExec</li>
</ul>

<br>

<h3> Known Errors </h3>
<h4> ⚠️ pip failed to build package: python-ldap </h4>
<pre>
sudo apt-get install libsasl2-dev python3-dev libldap2-dev libssl-dev
</pre>

<h4> ⚠️ breads has a 'pyproject.toml' and its build backend is missing the 'build_editable' hook. </h4>
<pre>
You need to install breads with pipx install git+https://github.com/oppsec/breads.git
</pre>

<br>

<h3> Warning </h3>
<p> The developer is not responsible for any malicious use of this tool </p>