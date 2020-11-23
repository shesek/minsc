export default

`// Liquid-like federated pegin with emergency recovery keys

$federation = 4 of [ pk(A), pk(B), pk(C), pk(D), pk(E) ]; 
$recovery = 2 of [ pk(F), pk(G), pk(I) ];
$timeout = older(3 months);

likely@$federation || ($timeout && $recovery)`
