library(jsonlite)
library(mitre)
library(burro)
library(dplyr)
library(ggplot2)
library(plyr)
library(markdown)
library(knitr)
library(stringr)
library(ggrepel)




capec.relations <- data.frame(capec.relations)
mitre <- subset(capec.relations,capec.relations$name == "ATTACK")
mitre2 <- subset(capec.relations,capec.relations$name == "ChildOf")
mitre3 <- subset(capec.relations,capec.relations$name == "take advantage of")

i <- 1
while (i <= nrow((CAPECordered)))
{
  aux <- list(subset(mitre,mitre$from == CAPECordered$CAPEC[i])[,3])
  if (length(grep("T",aux)) != 0)

    {
      CAPECordered$Relations[i] <- aux
  }else{
    aux <- list(subset(mitre2,mitre2$from == CAPECordered$CAPEC[i])[,3])
    if (length(grep("C",aux)) != 0)

        {
      CAPECordered$Relations[i] <- aux
         }else{
           aux <- list(subset(mitre3,mitre3$from == CAPECordered$CAPEC[i])[,3])

           if(length(grep("C",aux)) != 0)
           {
             CAPECordered$Relations[i] <- aux

           }else{

                CAPECordered$Relations[i] <- 0
                  }
        }
  }

  i <- i + 1
}

test <- data.frame(CAPECordered[grep("^T",CAPECordered$Relations),])

aux <- nrow(test)                               #Cuento todas las líneas de CWEs

MITRE <- data.frame(str_split(test$Relations[1],","))                 #Llevo a un nuevo dataframe todas los CVEs del primer CPE
#CAPEC <- unlist(strsplit(CAPEC$CAPEC[1], split=':', fixed=TRUE))[2]
colnames(MITRE) <- "Techniques"                               #Le pongo de nombre a la columna CVEs
i <- 2                                                #Auxiliar en 2

while (i <= aux){                                     #Voy añadiendo al dataframe anterior todas las listas de CVEs que existen en el dataframe CPE

  MITRE2 <- data.frame(str_split(test$Relations[i],","))
  colnames(MITRE2) <- "Techniques"
  MITRE <- rbind(MITRE,MITRE2)
  distinct(MITRE)
  i <- i + 1
}

i <- 2

while (i <= nrow(MITRE)){
  j <- i - 1

  while (j > 0){

    if (MITRE[i,1] == MITRE[j,1]){

      MITRE[i,1] <- 0
    }
    j <- j - 1

  }

  i <- i + 1
}

MITREf <- data.frame(MITRE[1,])
colnames(MITREf) <- c("Techniques")
i <- 2

while (i <= nrow(MITRE)){

  if(MITRE[i,1] != 0){
    MITREf <- rbind(MITREf,MITRE[i,])
  }

  i <- i + 1
}

MITREf$total <- lapply(lapply(MITREf[,1],test$Relations,FUN = grep), length)
MITREf$pos <- lapply(MITREf[,1],test$Relations,FUN = grep)
MITREf$total <- as.numeric(MITREf[,2])
MITREordered <- MITREf[order(MITREf$total,decreasing = TRUE),]

graphic1 <- ggplot(data = MITREordered, mapping = aes(x = total, y = Techniques, fill = as.factor(Techniques)))

graphic1 + geom_bar(stat = 'identity') +
  xlab("Total de Técnicas de Ataque") +
  ylab("Techniques") +
  ggtitle(paste("Gráfico de las técnicas de ataques presentes en",producto,sep = " ")) +
  labs(fill = "Techniques")


i <- 1
while (i<= nrow(MITREordered))
{
  MITREordered$CAPEC[i] <- CAPECordered$CAPEC[unlist(MITREf$pos[i])]
  aux <- grep(paste("^",MITREordered$Techniques[i],"$",sep=""),attck.techniques$external_id)
  if (length(aux)==1)
  {
   MITREordered$Name[i] <- attck.techniques$name[aux]
   MITREordered$Description[i] <- attck.techniques$description[aux]
   MITREordered$Url[i] <- attck.techniques$url[aux]
  }else{
    MITREordered$Name[i] <- attck.techniques$name[aux[1]]
    MITREordered$Description[i] <- attck.techniques$description[aux[1]]
    MITREordered$Url[i] <- attck.techniques$url[aux[1]]
      }
  i <- i + 1

}

shield.relations <- file.show("shield.relations.rda")
shield.techniques <- file.show("shield.techniques.rda")

