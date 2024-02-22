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
<p> <b>BREADS</b> is a tool focused to enumerate and attack Active Directory environments through LDAP, SMB and other protocols (not done yet). This project is inspired on other existing tools like CrackMapExec and NetExec. </p>

<br>

<h3> Why use this? </h3>
<p> This project is created and maintained by security researchers that want to study and discover more about Active Directory environments, then you don't need to use this necessary but I promise the team is trying his best to make this a really usable tool and a cool project </p>

<br>

<h3> Any advantage? </h3>
<p> Yes, the principal Breads advantages is the flexibility of creating profiles that is directed stored on the local machine (through the .breads directory created on user home) and the easy way to execute commands without needing to re-type the same credentials everytime. I personally like how 'whoami' command works and that's all. </p>

<br>

<h3> Installation </h3>
<pre>
~$ pipx install git+https://github.com/oppsec/breads
~$ pipx ensurepath
~$ breads-ad
</pre>

<br>

<h3> Credits </h3>
<li>CrackMapExec</li>
<li>Impacket</li>
<li>NetExec</li>

<br>

<h3> Warning </h3>
<p> The developer is not responsible for any malicious use of this tool </p>