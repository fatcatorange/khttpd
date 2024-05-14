reset
set terminal png
set title 'Duration vs Data Index'
set xlabel 'Data Index'
set ylabel 'Duration (ns)'
set output 'duration_plot.png'


data = 'output.txt'

plot data using 0:2 with linespoints title 'Duration'

