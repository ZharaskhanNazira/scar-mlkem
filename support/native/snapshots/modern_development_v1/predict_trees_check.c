#include <stdio.h>
#include "model_trees.h"
int main(void){double x[11];while(scanf("%lf",&x[0])==1){for(int i=1;i<11;i++)if(scanf("%lf",&x[i])!=1)return 2;printf("%.17g,%.17g\n",predict_rf(x),predict_hgb(x));}return 0;}
