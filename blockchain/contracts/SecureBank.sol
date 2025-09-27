// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title SecureBank
 * @dev Version sécurisée du smart contract bancaire qui implémente les bonnes pratiques
 * ✅ SÉCURISÉ - Implémente le pattern Checks-Effects-Interactions et ReentrancyGuard
 */
contract SecureBank {
    mapping(address => uint256) public balances;
    mapping(address => bool) public depositors;
    
    uint256 public totalDeposits;
    address public owner;
    bool public emergencyStop = false;
    
    // 🔒 SÉCURITÉ: Mutex pour prévenir la reentrancy
    bool private locked = false;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event EmergencyStop(bool stopped);
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
    
    modifier notStopped() {
        require(!emergencyStop, "Contract is stopped");
        _;
    }
    
    // 🔒 SÉCURITÉ: Modifier pour prévenir la reentrancy
    modifier nonReentrant() {
        require(!locked, "ReentrancyGuard: reentrant call");
        locked = true;
        _;
        locked = false;
    }
    
    constructor() {
        owner = msg.sender;
    }
    
    /**
     * @dev Fonction de dépôt sécurisée
     */
    function deposit() external payable notStopped nonReentrant {
        require(msg.value > 0, "Deposit amount must be greater than 0");
        
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        depositors[msg.sender] = true;
        
        emit Deposit(msg.sender, msg.value);
    }
    
    /**
     * @dev Fonction de retrait SÉCURISÉE - suit le pattern Checks-Effects-Interactions
     * ✅ SÉCURITÉ: État mis à jour AVANT l'appel externe
     */
    function withdraw(uint256 _amount) external notStopped nonReentrant {
        // 🔍 CHECKS: Vérifications d'abord
        require(_amount > 0, "Withdrawal amount must be greater than 0");
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        
        // ⚡ EFFECTS: Mise à jour de l'état AVANT l'appel externe
        balances[msg.sender] -= _amount;
        totalDeposits -= _amount;
        
        // 🔄 INTERACTIONS: Appel externe en dernier
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");
        
        emit Withdrawal(msg.sender, _amount);
    }
    
    /**
     * @dev Fonction de retrait d'urgence sécurisée
     * ✅ SÉCURITÉ: Même pattern Checks-Effects-Interactions
     */
    function emergencyWithdraw() external notStopped nonReentrant {
        // 🔍 CHECKS
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance to withdraw");
        
        // ⚡ EFFECTS: Mise à jour AVANT l'appel externe
        balances[msg.sender] = 0;
        totalDeposits -= balance;
        depositors[msg.sender] = false;
        
        // 🔄 INTERACTIONS: Appel externe en dernier
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
        
        emit Withdrawal(msg.sender, balance);
    }
    
    /**
     * @dev Alternative de retrait avec pull pattern (encore plus sécurisé)
     * Les utilisateurs doivent appeler cette fonction pour "marquer" leur retrait
     * puis appeler claimWithdrawal() pour récupérer les fonds
     */
    mapping(address => uint256) public pendingWithdrawals;
    
    function requestWithdrawal(uint256 _amount) external notStopped nonReentrant {
        require(_amount > 0, "Withdrawal amount must be greater than 0");
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        require(pendingWithdrawals[msg.sender] == 0, "Withdrawal already pending");
        
        // Mise à jour de l'état
        balances[msg.sender] -= _amount;
        totalDeposits -= _amount;
        pendingWithdrawals[msg.sender] = _amount;
    }
    
    function claimWithdrawal() external nonReentrant {
        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "No pending withdrawal");
        
        // Réinitialiser avant le transfert
        pendingWithdrawals[msg.sender] = 0;
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit Withdrawal(msg.sender, amount);
    }
    
    /**
     * @dev Fonction de retrait avec limite de gas (protection supplémentaire)
     */
    function withdrawWithGasLimit(uint256 _amount) external notStopped nonReentrant {
        require(_amount > 0, "Withdrawal amount must be greater than 0");
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        
        // Mise à jour de l'état AVANT l'appel externe
        balances[msg.sender] -= _amount;
        totalDeposits -= _amount;
        
        // Appel externe avec limite de gas (2300 gas - suffisant pour un EOA, pas pour un contrat complexe)
        (bool success, ) = msg.sender.call{value: _amount, gas: 2300}("");
        require(success, "Transfer failed");
        
        emit Withdrawal(msg.sender, _amount);
    }
    
    /**
     * @dev Fonction pour vérifier le solde d'un utilisateur
     */
    function getBalance(address _user) external view returns (uint256) {
        return balances[_user];
    }
    
    /**
     * @dev Fonction pour obtenir le solde du contrat
     */
    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }
    
    /**
     * @dev Fonction d'arrêt d'urgence (circuit breaker)
     */
    function toggleEmergencyStop() external onlyOwner {
        emergencyStop = !emergencyStop;
        emit EmergencyStop(emergencyStop);
    }
    
    /**
     * @dev Fonction pour récupérer les fonds en cas d'urgence (owner seulement)
     */
    function emergencyDrain() external onlyOwner nonReentrant {
        require(emergencyStop, "Emergency stop must be activated");
        
        uint256 contractBalance = address(this).balance;
        (bool success, ) = owner.call{value: contractBalance}("");
        require(success, "Emergency drain failed");
    }
    
    /**
     * @dev Fonction pour obtenir la liste des déposants
     */
    function isDepositor(address _user) external view returns (bool) {
        return depositors[_user];
    }
    
    /**
     * @dev Fonction pour obtenir des statistiques du contrat
     */
    function getContractStats() external view returns (
        uint256 contractBalance,
        uint256 totalDepositsAmount,
        bool isStopped,
        bool contractLocked
    ) {
        return (
            address(this).balance,
            totalDeposits,
            emergencyStop,
            locked
        );
    }
    
    /**
     * @dev Fonction pour obtenir les retraits en attente
     */
    function getPendingWithdrawal(address _user) external view returns (uint256) {
        return pendingWithdrawals[_user];
    }
    
    /**
     * @dev Fonction pour annuler un retrait en attente (en cas d'urgence)
     */
    function cancelPendingWithdrawal() external nonReentrant {
        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "No pending withdrawal");
        
        // Remettre les fonds dans le solde
        pendingWithdrawals[msg.sender] = 0;
        balances[msg.sender] += amount;
        totalDeposits += amount;
    }
    
    /**
     * @dev Fonction fallback sécurisée pour recevoir de l'ETH
     */
    receive() external payable nonReentrant {
        require(msg.value > 0, "Must send ETH");
        
        // Accepter les paiements directs
        totalDeposits += msg.value;
        balances[msg.sender] += msg.value;
        depositors[msg.sender] = true;
        emit Deposit(msg.sender, msg.value);
    }
    
    /**
     * @dev Fonction fallback générale
     */
    fallback() external payable {
        revert("Function not found");
    }
    
    /**
     * @dev Fonction pour vérifier si le contrat est verrouillé (pour les tests)
     */
    function isLocked() external view returns (bool) {
        return locked;
    }
    
    /**
     * @dev Fonction pour obtenir la version du contrat
     */
    function getVersion() external pure returns (string memory) {
        return "SecureBank v1.0 - Reentrancy Protected";
    }
}