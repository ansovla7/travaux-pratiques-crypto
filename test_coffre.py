import pytest
from cryptography.exceptions import InvalidTag
import coffre
MDP, NOM, DATA = "correct horse battery staple", "rapport.pdf", b"contenu secret " *100

@pytest.fixture(scope="module")
def blob():
	return coffre.chiffrer(MDP, NOM, DATA)

def test_aller_retour(blob):
	assert coffre.dechiffrer(MDP, NOM, blob) == DATA

def test_chiffrement_probabiliste(blob):
	autre = coffre.chiffrer(MDP, NOM, DATA)
	assert autre != blob
	assert autre[16:32] != blob[16:32]
	assert autre[32:44] != blob[32:44]

def test_mauvais_mot_de_passe(blob):
	with pytest.raises(InvalidTag):
	coffre.dechiffrer("mauvais", NOM, blob)

def test_octet_modifie(blob):
	b = bytearray(blob)
	b[-20] ^= 0x01
	with pytest.raises(InvalidTag):
	coffre.dechiffrer(MDP, NOM, bytes(b))

def test_fichier_renomme(blob):
	with pytest.raises(InvalidTag):
	coffre.dechiffrer(MDP, "facture.pdf", blob)

def test_entete_modifie(blob):
	b = bytearray(blob)
	b[8] ^= 0x01
	with pytest.raises((InvalidTag, Exception)):
	coffre.dechiffrer(MDP, NOM, bytes(b))

def test_format_inconnu(blob):
	with pytest.raises(ValueError):
	coffre.dechiffrer(MDP, NOM, b"CFR9" + blob[4:])

def test_rechiffrer(blob):
	nouveau = coffre.rechiffrer(MDP, "nouveau mdp", NOM, blob)
	assert coffre.dechiffrer("nouveau mdp", NOM, nouveau) == DATA
	with pytest.raises(InvalidTag):
	coffre.dechiffrer(MDP, NOM, nouveau)

def test_anciens_parametres_lisibles():
	ancien = coffre.chiffrer(MDP, NOM, DATA, t=2, m=19 * 1024, p=1)
	assert coffre.dechiffrer(MDP, NOM, ancien) == DATA

def test_sous_cles_independantes():
	k = b"\x00" * 32
	assert coffre.sous_cle(k, b"chiffrement") != coffre.sous_cle(k, b"mac")
