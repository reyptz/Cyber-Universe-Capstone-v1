pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

template PasswordVerification() {
    // Signaux d'entrée privés (secrets)
    signal private input password;
    
    // Signaux d'entrée publics
    signal input expectedHash;
    
    // Signal de sortie
    signal output isValid;
    
    // Composant pour calculer le hash Poseidon
    component hasher = Poseidon(1);
    hasher.inputs[0] <== password;
    
    // Vérifier que le hash calculé correspond au hash attendu
    component isEqual = IsEqual();
    isEqual.in[0] <== hasher.out;
    isEqual.in[1] <== expectedHash;
    
    // Le résultat indique si le mot de passe est correct
    isValid <== isEqual.out;
}

template IsEqual() {
    signal input in[2];
    signal output out;
    
    component isz = IsZero();
    isz.in <== in[1] - in[0];
    out <== isz.out;
}

template IsZero() {
    signal input in;
    signal output out;
    
    signal inv;
    inv <-- in != 0 ? 1/in : 0;
    
    out <== -in*inv + 1;
    in*out === 0;
}

component main = PasswordVerification();