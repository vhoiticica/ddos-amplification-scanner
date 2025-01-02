# ddos-amplification-scanner

Aviso Legal: Este projeto foi desenvolvido como uma ferramenta de prevenção e estudo, com o objetivo de ajudar a proteger redes contra ataques de amplificação DRDoS. O uso da ferramenta para identificar e testar a vulnerabilidade de servidores ou redes a esse tipo de ataque deve ser feito com responsabilidade. O desenvolvedor não se responsabiliza por quaisquer danos causados por uso indevido ou malicioso.

Este projeto oferece uma ferramenta para detectar e testar serviços vulneráveis a ataques de amplificação DRDoS em redes. O scanner realiza uma série de testes em portas UDP/TCP para identificar serviços expostos e suscetíveis, como NetBIOS, RPC, TFTP, DNS, entre outros, em blocos de IPs especificados. Além disso, a ferramenta verifica a presença de loops na rede, o que pode amplificar os efeitos de um ataque DDoS, caso esses IPs estejam no backbone da rede. O repositório inclui scripts para testar a presença de serviços de amplificação, detectar loops e coletar resultados para análises posteriores.

Além disso, foram adicionados scripts para simular eventos de DRDoS. Recomenda-se fortemente que você configure seu próprio servidor em um ambiente controlado para executar esses códigos, de forma a evitar qualquer impacto indesejado em redes ou serviços externos.
