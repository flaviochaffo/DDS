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
library(xml2)


i <- 1
while (i<= nrow(MITREordered))
{
  aux <- grep(paste("^",MITREordered$Techniques[i],"$",sep=""),shield.relations$to)
  if (length(aux)>=1)
  {
    MITREordered$Shield[i] <- list(shield.relations$from[aux])

  }else{
    aux <- grep(paste("^",substring(MITREordered$Techniques[i],1,str_length(MITREordered$Techniques[i])-4),"$",sep=""),shield.relations$to)
    MITREordered$Shield[i] <- list(shield.relations$from[aux])
    }
  i <- i + 1

}

i <- 1

MITRESHIELD <- MITREordered[1,]
MITRESHIELD <- MITRESHIELD[-1,]

while(i<=nrow(MITREordered))
{
  j <- length(unlist(MITREordered$Shield[i]))


  if (j>1)
  {

    aux <- 0

    while (aux < j)
    {
      MITRESHIELD <- rbind(MITRESHIELD,MITREordered[i,])
      MITRESHIELD[i+aux,ncol(MITRESHIELD)] <- unlist(MITREordered$Shield[i])[aux+1]
      aux <- aux + 1

    }



  }else
    {
      MITRESHIELD <- rbind(MITRESHIELD,MITREordered[i,])
    }

  i <- i + j

}

i <- 1

while (i<= nrow(MITRESHIELD))
{
  aux <- grep(paste("^",MITRESHIELD$Shield[i],"$",sep=""),shield.techniques$id)
  MITRESHIELD$ShieldName[i] <- unlist(shield.techniques$name[aux])
  MITRESHIELD$ShieldDesc[i] <- list(shield.techniques$description[aux])
  i <- i + 1

}

MITRESHIELD$ShieldName <- unlist(MITRESHIELD$ShieldName)

graphic2 <- ggplot(data = MITRESHIELD, mapping = aes(ShieldName,Name))

graphic2 + geom_point() + # Show dots

  geom_label(
    label=MITRESHIELD$CAPEC,
    nudge_x = 0, nudge_y = 0,aes(fill = factor(total)), colour = "white", fontface = "bold"

  ) +
  xlab("Técnicas de Defensa") +
  ylab("Técnicas de Ataque") +
  ggtitle(paste("Técnicas de Defensa vs Técnicas de Ataque y sus respectivas CAPEC de",producto,sep = " ")) +
  labs(fill = "CAPEC")+ theme_light()


