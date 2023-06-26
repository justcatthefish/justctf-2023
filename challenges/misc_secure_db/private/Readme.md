### Secure DB
Task oparty o wykonanie wyszukania wiersza po id w zaszyfrowanej tablicy. 
Sekwencyjne szukanie ma w założeniu trwać za długo więc trzeba pomyśleć o jakimś zrównolegleniu.

Skrypt build_static generuje klucze i bazę dla zadania oraz zestaw kluczy i bazę dla testów do folderu public
#### Generating static data
w folderze private/initializer
./build_static.sh

#### Running task
Muszą być wcześniej wygenerowane klucze
./run.sh

#### Running solver
w folderze private/solver
./solve.sh