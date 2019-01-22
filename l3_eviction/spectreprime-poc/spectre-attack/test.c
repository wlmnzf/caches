#include<stdio.h>
#include<stdlib.h>
int main()
{
int size = 5;
int *elements = malloc(sizeof(int)*size);

// inizialize
for (int i = 0; i < size; ++i)
  elements[i] = i;

for (int i = size - 1; i > 0; --i) {
  // generate random index
  int w = rand()%i;
  // swap items
  int t = elements[i];
  elements[i] = elements[w];
  elements[w] = t;
}
for (int i = size - 1; i >=0; --i) {
   printf("%d\n",elements[i]);
}

  return 0;
}